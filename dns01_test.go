// SPDX-License-Identifier: BSD-3-Clause

package servercert

// dns-01 against pebble, in-process, with a DNS stub that answers the TXT
// records a test solver publishes (the model of pebble's challenge test
// server: the CA's own validator does the lookup). The control publishes a
// wrong value and must be refused.

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// txtZone is a DNS server answering TXT queries from what a solver published.
type txtZone struct {
	mu     sync.Mutex
	txt    map[string][]string
	peak   map[string]int // most values ever at once, by name
	events []string
	addr   string
	failOn string // Present returns an error for this name
	mangle bool   // publish a wrong value

	failClean bool // CleanUp returns an error
}

func newTXTZone(t *testing.T) *txtZone {
	t.Helper()
	z := &txtZone{txt: map[string][]string{}, peak: map[string]int{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		z.mu.Lock()
		for _, q := range r.Question {
			if q.Qtype == dns.TypeTXT {
				for _, v := range z.txt[strings.ToLower(q.Name)] {
					m.Answer = append(m.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
						Txt: []string{v},
					})
				}
			}
		}
		z.mu.Unlock()
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	z.addr = ln.Addr().String()
	return z
}

func (z *txtZone) Present(_ context.Context, name, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.events = append(z.events, "present "+name)
	if z.failOn == name {
		return errors.New("provider refused")
	}
	if z.mangle {
		value = "x" + value
	}
	z.txt[name] = append(z.txt[name], value)
	z.peak[name] = max(z.peak[name], len(z.txt[name]))
	return nil
}

func (z *txtZone) CleanUp(_ context.Context, name, value string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.events = append(z.events, "cleanup "+name)
	if z.failClean {
		return errors.New("cleanup refused")
	}
	if z.mangle {
		value = "x" + value
	}
	var keep []string
	for _, v := range z.txt[name] {
		if v != value {
			keep = append(keep, v)
		}
	}
	if len(keep) == 0 {
		delete(z.txt, name)
	} else {
		z.txt[name] = keep
	}
	return nil
}

func (z *txtZone) left() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	n := 0
	for _, v := range z.txt {
		n += len(v)
	}
	return n
}

func dnsSource(t *testing.T, p *pebble, z *txtZone, cache string, domains []string) (*Source, *errs) {
	t.Helper()
	return acmeSource(t, p, cache, func(a *ACME) {
		a.Domains = domains
		a.DNS = &DNS{Solver: z, Resolver: z.addr, PropagationWait: -1}
	})
}

func TestPebbleDNS01(t *testing.T) {
	z := newTXTZone(t)
	// No tls-alpn-01 and no http-01 port: only the TXT record can prove it.
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	cache := filepath.Join(t.TempDir(), "cache")
	s, got := dnsSource(t, p, z, cache, []string{domain})
	ln, _ := freePort(t)
	addr := serveOn(t, ln, s.TLSConfig())

	issued(t, addr, p)
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError told %v", e)
	}
	if n := z.left(); n != 0 {
		t.Errorf("%d TXT records left behind", n)
	}
	if z.peak["_acme-challenge."+domain+"."] != 1 {
		t.Errorf("events %v", z.events)
	}
	if fi, err := os.Stat(filepath.Join(cache, certFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0) {
		t.Errorf("cached certificate: %v, %v", fi, err)
	}

	// A name outside Domains gets nothing and costs OnError nothing.
	if _, err := dial(addr, "other.servercert.test", p.roots); err == nil {
		t.Error("a name outside Domains got a certificate")
	}
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError was told about a stranger's name: %v", e)
	}

	// A new source on the same cache serves the cached certificate without
	// asking anybody: a solver that refuses everything is never called.
	z.mu.Lock()
	z.failOn = "_acme-challenge." + domain + "."
	z.events = nil
	z.mu.Unlock()
	s2, _ := dnsSource(t, p, z, cache, []string{domain})
	ln2, _ := freePort(t)
	issued(t, serveOn(t, ln2, s2.TLSConfig()), p)
	if len(z.events) != 0 {
		t.Errorf("the cache was not used: %v", z.events)
	}
}

func TestPebbleDNS01Wildcard(t *testing.T) {
	z := newTXTZone(t)
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	s, got := dnsSource(t, p, z, filepath.Join(t.TempDir(), "cache"), []string{"*." + domain, domain})
	ln, _ := freePort(t)
	addr := serveOn(t, ln, s.TLSConfig())

	if err := s.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{domain, "a." + domain, "b." + domain} {
		leaf, err := dial(addr, name, p.roots)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(leaf.DNSNames) != 2 {
			t.Errorf("names %v", leaf.DNSNames)
		}
	}
	// Two authorizations, one record name: both values stood there together.
	if z.peak["_acme-challenge."+domain+"."] != 2 {
		t.Errorf("peak %v, events %v", z.peak, z.events)
	}
	if z.left() != 0 {
		t.Errorf("%d records left", z.left())
	}
	// Two labels below the wildcard are not covered by it (RFC 6125 §6.4.3).
	if _, err := dial(addr, "x.y."+domain, p.roots); err == nil {
		t.Error("a name two labels below the wildcard got a certificate")
	}
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError told %v", e)
	}
}

// TestPebbleDNS01WrongRecord is the control: the same flow with a TXT value
// that is not the key authorization's digest. The CA refuses, nothing is
// issued or cached, the record is still removed, and OnError says so.
func TestPebbleDNS01WrongRecord(t *testing.T) {
	z := newTXTZone(t)
	z.mangle = true
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	cache := filepath.Join(t.TempDir(), "cache")
	// No Resolver check: it would notice the value is not the one asked for
	// and wait for it (see TestPebbleDNS01ResolverWaits); here the CA judges.
	s, got := acmeSource(t, p, cache, func(a *ACME) {
		a.DNS = &DNS{Solver: z, PropagationWait: -1}
	})
	ln, _ := freePort(t)
	addr := serveOn(t, ln, s.TLSConfig())

	if _, err := dial(addr, domain, p.roots); err == nil {
		t.Fatal("a certificate was issued for a wrong TXT record")
	}
	if len(got.get()) == 0 {
		t.Error("OnError was not told")
	}
	if z.left() != 0 {
		t.Errorf("%d records left after a failed order", z.left())
	}
	if _, err := os.Stat(filepath.Join(cache, certFile)); err == nil {
		t.Error("a certificate was cached")
	}
	// The failure is remembered: the next handshake does not ask the CA again.
	n := len(z.events)
	if _, err := dial(addr, domain, p.roots); err == nil {
		t.Error("issued on retry")
	}
	if len(z.events) != n {
		t.Errorf("the CA was asked again within %v: %v", retryAfter, z.events[n:])
	}
}

// TestPebbleDNS01ResolverWaits: with a Resolver, a record that never becomes
// visible with the right value stops the order before the CA is asked.
func TestPebbleDNS01ResolverWaits(t *testing.T) {
	z := newTXTZone(t)
	z.mangle = true
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	s, _ := acmeSource(t, p, filepath.Join(t.TempDir(), "cache"), func(a *ACME) {
		a.DNS = &DNS{Solver: z, Resolver: z.addr, PropagationWait: -1, Timeout: 3 * time.Second}
	})
	err := s.Prefetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not visible") {
		t.Fatalf("Prefetch: %v", err)
	}
	if z.left() != 0 {
		t.Errorf("%d records left", z.left())
	}
}

func TestPebbleDNS01ProviderFails(t *testing.T) {
	z := newTXTZone(t)
	z.failOn = "_acme-challenge." + domain + "."
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	s, got := dnsSource(t, p, z, filepath.Join(t.TempDir(), "cache"), []string{domain})
	err := s.Prefetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "provider refused") {
		t.Fatalf("Prefetch: %v", err)
	}
	if len(got.get()) == 0 {
		t.Error("OnError was not told")
	}
}

func TestDNSConfigChecks(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "creds")
	if err := os.WriteFile(kf, []byte("secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func(f func(*ACME)) Config {
		a := &ACME{Domains: []string{"files.example.org"}, CacheDir: filepath.Join(t.TempDir(), "c"),
			DNS: &DNS{Solver: &txtZone{}}}
		f(a)
		return Config{ACME: a}
	}
	for name, tc := range map[string]struct {
		c    Config
		want string // "" = accepted
	}{
		"wildcard with dns":    {base(func(a *ACME) { a.Domains = []string{"*.example.org"} }), ""},
		"wildcard without dns": {base(func(a *ACME) { a.Domains = []string{"*.example.org"}; a.DNS = nil }), "set ACME.DNS"},
		"ip with dns":          {base(func(a *ACME) { a.Domains = []string{"192.0.2.1"} }), "IP address"},
		"star only":            {base(func(a *ACME) { a.Domains = []string{"*"} }), "wildcard"},
		"double star":          {base(func(a *ACME) { a.Domains = []string{"*.*.example.org"} }), "wildcard"},
		"star inside":          {base(func(a *ACME) { a.Domains = []string{"a.*.example.org"} }), "wildcard"},
		"star label part":      {base(func(a *ACME) { a.Domains = []string{"*a.example.org"} }), "wildcard"},
		"wildcard tld":         {base(func(a *ACME) { a.Domains = []string{"*.org"} }), "single label"},
		"http-01 too":          {base(func(a *ACME) { a.HTTPChallenge = true }), "exclusive"},
		"no provider":          {base(func(a *ACME) { a.DNS = &DNS{} }), "needs a Solver"},
		"both":                 {base(func(a *ACME) { a.DNS = &DNS{Solver: &txtZone{}, CredentialsFile: kf} }), "exclusive"},
		"provider no file":     {base(func(a *ACME) { a.DNS = &DNS{Provider: func([]byte) (DNSSolver, error) { return nil, nil }} }), "needs a Solver"},
		"relative file": {base(func(a *ACME) {
			a.DNS = &DNS{CredentialsFile: "creds", Provider: func([]byte) (DNSSolver, error) { return nil, nil }}
		}), "absolute"},
		"resolver no port": {base(func(a *ACME) { a.DNS.Resolver = "127.0.0.1" }), "host:port"},
	} {
		err := tc.c.Check()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestDNSCredentialsFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("tsig-secret-bytes"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var seen string
	provider := func(b []byte) (DNSSolver, error) { seen = string(b); return &txtZone{}, nil }
	cfg := func(file string) Config {
		return Config{ACME: &ACME{Domains: []string{"files.example.org"}, CacheDir: filepath.Join(t.TempDir(), "c"),
			DNS: &DNS{CredentialsFile: file, Provider: provider}}}
	}

	if _, err := New(cfg(write("ok", 0o600))); err != nil || seen != "tsig-secret-bytes" {
		t.Fatalf("0600 file: %v, provider saw %q", err, seen)
	}
	seen = ""
	if runtime.GOOS != "windows" { // mode bits do not describe access there
		if _, err := New(cfg(write("open", 0o644))); err == nil || seen != "" {
			t.Errorf("a group/other-readable credentials file: %v, provider saw %q", err, seen)
		} else if strings.Contains(err.Error(), "tsig-secret-bytes") {
			t.Errorf("the error quotes the secret: %v", err)
		}
	}
	if _, err := New(cfg(filepath.Join(dir, "missing"))); err == nil {
		t.Error("a missing credentials file was accepted")
	}
	bad := Config{ACME: &ACME{Domains: []string{"files.example.org"}, CacheDir: filepath.Join(t.TempDir(), "c"),
		DNS: &DNS{CredentialsFile: write("bad", 0o600), Provider: func(b []byte) (DNSSolver, error) {
			return nil, errors.New("cannot parse " + string(b))
		}}}}
	// A provider that echoes the secret in its error is its own fault, but
	// the file name is what this package adds.
	if _, err := New(bad); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("provider error: %v", err)
	}
}

func TestDNSServes(t *testing.T) {
	is := &dnsIssuer{domains: []string{"*.example.org", "example.org", "www.other.org"}}
	for name, want := range map[string]bool{
		"example.org": true, "A.Example.ORG": true, "a.example.org.": true, "a.b.example.org": false,
		".example.org": false, "www.other.org": true, "x.other.org": false, "org": false,
	} {
		if got := is.serves(name); got != want {
			t.Errorf("serves(%q) = %v", name, got)
		}
	}
}
