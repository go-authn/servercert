// SPDX-License-Identifier: BSD-3-Clause

package servercert

// These tests obtain real certificates from pebble, Let's Encrypt's own test
// CA, run in-process from its packages (ca, db, va, wfe) exactly as its
// cmd/pebble wires them. Pebble is the judge: it validates the challenges
// our listener answers, refuses the EAB it does not know, and signs with a
// root this package never sees except to hand to a TLS client.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
)

const domain = "files.servercert.test"

// syncBuf is pebble's log, shown only when a test fails.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// resolver is a DNS server (TCP, as pebble's VA asks) that sends every name
// to 127.0.0.1, so the VA reaches our loopback listeners.
func resolver(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
					A:   net.IPv4(127, 0, 0, 1),
				})
			}
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return ln.Addr().String()
}

type pebble struct {
	dirURL string
	client *http.Client   // trusts pebble's API certificate
	roots  *x509.CertPool // pebble's issuing root, for the TLS client
}

// startPebble runs pebble with its VA pointed at tlsPort (tls-alpn-01) and
// httpPort (http-01). eab non-nil makes External Account Binding required,
// with those key IDs and base64url HMAC keys.
func startPebble(t *testing.T, tlsPort, httpPort int, eab map[string]string, authzReuse string) *pebble {
	t.Helper()
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")        // no random 0-5 s sleep before validating
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")   // no deliberately rejected nonces
	t.Setenv("PEBBLE_AUTHZREUSE", authzReuse) // 0: every order is validated
	logs := &syncBuf{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("pebble log:\n%s", logs)
		}
	})
	logger := log.New(logs, "pebble ", log.Lmicroseconds)

	store := db.NewMemoryStore()
	profiles := map[string]ca.Profile{"default": {Description: "default"}}
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, profiles)
	validator := va.New(logger, httpPort, tlsPort, false, resolver(t), store)
	for kid, key := range eab {
		if err := store.AddExternalAccountKeyByID(kid, key); err != nil {
			t.Fatal(err)
		}
	}
	front := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, eab != nil, 0, 0)
	srv := httptest.NewTLSServer(front.Handler())
	t.Cleanup(srv.Close)

	roots := x509.NewCertPool()
	roots.AddCert(authority.GetRootCert(0).Cert)
	return &pebble{dirURL: srv.URL + wfe.DirectoryPath, client: srv.Client(), roots: roots}
}

func freePort(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// closedPort is a port nothing listens on (bound, then released).
func closedPort(t *testing.T) int {
	ln, port := freePort(t)
	ln.Close()
	return port
}

func acmeSource(t *testing.T, p *pebble, cache string, f func(*ACME)) (*Source, *errs) {
	t.Helper()
	a := &ACME{
		DirectoryURL: p.dirURL,
		Email:        "admin@servercert.test",
		Domains:      []string{domain},
		CacheDir:     cache,
		HTTPClient:   p.client,
	}
	if f != nil {
		f(a)
	}
	got := &errs{}
	s, err := New(Config{ACME: a, OnError: got.add})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, got
}

// issued asserts a verified handshake: the TLS client checks the chain up to
// pebble's root and the name, which nothing in this package takes part in.
func issued(t *testing.T, addr string, p *pebble) {
	t.Helper()
	leaf, err := dial(addr, domain, p.roots)
	if err != nil {
		t.Fatalf("no certificate pebble's root vouches for: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
		t.Fatalf("certificate for %v, want %s", leaf.DNSNames, domain)
	}
}

func TestPebbleTLSALPN01(t *testing.T) {
	ln, port := freePort(t)
	p := startPebble(t, port, closedPort(t), nil, "0")
	s, got := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), nil)
	addr := serveOn(t, ln, s.TLSConfig())

	issued(t, addr, p)
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError told %v", e)
	}

	// A client by IP sends no SNI and gets nothing, as documented.
	if _, err := dial(addr, "", p.roots); err == nil {
		t.Error("a client without SNI got a certificate")
	}
	// A name we do not serve fails without troubling OnError.
	if _, err := dial(addr, "other.servercert.test", p.roots); err == nil {
		t.Error("a name outside Domains got a certificate")
	}
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError was told about a stranger's name: %v", e)
	}
}

// TestPebblePreValidated is the GÉANT TCS / HARICA case: the CA already
// holds a valid authorization for the domain, the order comes back "ready",
// and a certificate is issued although NOTHING answers a challenge port.
func TestPebblePreValidated(t *testing.T) {
	ln, port := freePort(t)
	p := startPebble(t, port, closedPort(t), nil, "100")
	cache := filepath.Join(t.TempDir(), "cache")

	// First the account validates the domain once, the ordinary way.
	first, _ := acmeSource(t, p, cache, nil)
	firstAddr := serveOn(t, ln, first.TLSConfig())
	issued(t, firstAddr, p)
	ln.Close() // pebble's tls-alpn-01 port is now closed for good

	// Same account (key in the cache), certificate removed from it.
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), domain) {
			if err := os.Remove(filepath.Join(cache, e.Name())); err != nil {
				t.Fatal(err)
			}
			removed++
		}
	}
	if removed == 0 {
		t.Fatalf("no cached certificate to remove in %v: the second issuance would be served from the cache", entries)
	}
	second, got := acmeSource(t, p, cache, nil)
	issued(t, serve(t, second.TLSConfig()), p)
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError told %v", e)
	}
}

// TestPebbleNoChallengePortFails is the control for TestPebblePreValidated:
// without the prior authorization, the same closed port means no certificate.
func TestPebbleNoChallengePortFails(t *testing.T) {
	p := startPebble(t, closedPort(t), closedPort(t), nil, "0")
	s, got := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), nil)
	if _, err := dial(serve(t, s.TLSConfig()), domain, p.roots); err == nil {
		t.Fatal("issued with no challenge answerable")
	}
	if e := got.get(); len(e) == 0 || !strings.Contains(e[0].Error(), domain) {
		t.Fatalf("OnError got %v, want the failure for %s", e, domain)
	}
}

func TestPebbleEAB(t *testing.T) {
	right := base64.RawURLEncoding.EncodeToString([]byte("an HMAC key of thirty-two bytes!"))
	wrong := base64.RawURLEncoding.EncodeToString([]byte("another key, also 32 bytes long."))
	ln, port := freePort(t)
	p := startPebble(t, port, closedPort(t), map[string]string{"kid-1": right}, "0")
	dir := t.TempDir()
	keyFile := func(name, key string) string {
		path := filepath.Join(dir, name)
		write(t, path, []byte(key+"\n"))
		return path
	}

	// Required and absent: refused.
	none, noneErr := acmeSource(t, p, filepath.Join(dir, "c0"), nil)
	if _, err := dial(serve(t, none.TLSConfig()), domain, p.roots); err == nil {
		t.Error("issued without EAB where pebble requires it")
	}
	// Required and wrong: refused.
	bad, badErr := acmeSource(t, p, filepath.Join(dir, "c1"), func(a *ACME) {
		a.EABKeyID, a.EABHMACKeyFile = "kid-1", keyFile("wrong", wrong)
	})
	if _, err := dial(serve(t, bad.TLSConfig()), domain, p.roots); err == nil {
		t.Error("issued with the wrong EAB HMAC key")
	}
	// Unknown key ID: refused.
	unknown, _ := acmeSource(t, p, filepath.Join(dir, "c2"), func(a *ACME) {
		a.EABKeyID, a.EABHMACKeyFile = "kid-2", keyFile("right2", right)
	})
	if _, err := dial(serve(t, unknown.TLSConfig()), domain, p.roots); err == nil {
		t.Error("issued with an EAB key ID pebble does not know")
	}
	for name, e := range map[string][]error{"no EAB": noneErr.get(), "wrong EAB": badErr.get()} {
		if len(e) == 0 {
			t.Errorf("%s: OnError was not told", name)
		}
	}

	// Positive control, same pebble, same test: the right key is issued.
	good, goodErr := acmeSource(t, p, filepath.Join(dir, "c3"), func(a *ACME) {
		a.EABKeyID, a.EABHMACKeyFile = "kid-1", keyFile("right", right)
	})
	issued(t, serveOn(t, ln, good.TLSConfig()), p)
	if e := goodErr.get(); len(e) != 0 {
		t.Fatalf("OnError told %v", e)
	}
}

func TestPebbleHTTP01(t *testing.T) {
	httpLn, httpPort := freePort(t)
	// tls-alpn-01 cannot succeed (closed port): autocert falls back to
	// http-01, which only HTTPHandler answers.
	p := startPebble(t, closedPort(t), httpPort, nil, "0")
	s, _ := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), func(a *ACME) { a.HTTPChallenge = true })

	var hits sync.Map
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Store(r.URL.Path, true)
		http.NotFound(w, r)
	})
	hs := &http.Server{Handler: s.HTTPHandler(fallback), ReadHeaderTimeout: time.Minute}
	go hs.Serve(httpLn)
	t.Cleanup(func() { hs.Close() })

	issued(t, serve(t, s.TLSConfig()), p)
	hits.Range(func(k, _ any) bool {
		if strings.HasPrefix(k.(string), "/.well-known/acme-challenge/") {
			t.Errorf("the challenge %s reached the fallback", k)
		}
		return true
	})
}

// TestPebbleHTTP01Off is the control for TestPebbleHTTP01: the same set-up
// without HTTPChallenge gets no certificate.
func TestPebbleHTTP01Off(t *testing.T) {
	httpLn, httpPort := freePort(t)
	p := startPebble(t, closedPort(t), httpPort, nil, "0")
	s, _ := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), nil)
	hs := &http.Server{Handler: s.HTTPHandler(nil), ReadHeaderTimeout: time.Minute}
	go hs.Serve(httpLn)
	t.Cleanup(func() { hs.Close() })
	_, err := dial(serve(t, s.TLSConfig()), domain, p.roots)
	if err == nil {
		t.Fatal("issued through http-01 although HTTPChallenge is off")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("timed out rather than refused: %v", err)
	}
}

// TestPebbleNeedsOrderLocations is the control for orderLocations: the same
// issuance with the CA client's transport left bare fails the way
// x/crypto/acme fails against a CA that finalizes asynchronously.
func TestPebbleNeedsOrderLocations(t *testing.T) {
	ln, port := freePort(t)
	p := startPebble(t, port, closedPort(t), nil, "0")
	s, got := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), nil)
	s.mgr.Client.HTTPClient = p.client
	if _, err := dial(serveOn(t, ln, s.TLSConfig()), domain, p.roots); err == nil {
		t.Fatal("issued without orderLocations: the workaround is no longer needed, remove it")
	}
	if e := got.get(); len(e) == 0 || !strings.Contains(e[0].Error(), `unsupported protocol scheme ""`) {
		t.Fatalf("OnError got %v, want the empty order URL failure", e)
	}
}
