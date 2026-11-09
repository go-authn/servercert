// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// selfSignedPEM is a key and a self-signed certificate, as the issuer caches
// them.
func selfSignedPEM(t *testing.T, names []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: notBefore, NotAfter: notAfter, DNSNames: names,
	}, &x509.Certificate{}, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return append(pemKey(k), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not describe access on Windows")
	}
}

// deadCA is a directory URL nothing answers on: an issuance fails at once.
const deadCA = "https://127.0.0.1:1/directory"

func cacheWith(t *testing.T, files map[string][]byte, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newDNS(t *testing.T, cache string, f func(*ACME)) (*Source, *errs, error) {
	t.Helper()
	a := &ACME{DirectoryURL: deadCA, Domains: []string{domain}, CacheDir: cache,
		DNS: &DNS{Solver: &txtZone{}, PropagationWait: -1}}
	if f != nil {
		f(a)
	}
	got := &errs{}
	s, err := New(Config{ACME: a, OnError: got.add})
	if s != nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, got, err
}

func TestMustPanicsOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("no panic")
		}
	}()
	must(0, errors.New("entropy"))
}

func TestWritePrivate(t *testing.T) {
	dir := t.TempDir()
	if err := writePrivate(filepath.Join(dir, "f"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "f")); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("%v, %v", fi, err)
	}
	if err := writePrivate(filepath.Join(dir, "missing", "f"), nil); err == nil {
		t.Error("a directory that is not there")
	}
	busy := filepath.Join(dir, "busy")
	if err := os.MkdirAll(filepath.Join(busy, "inside"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(busy, []byte("x")); err == nil {
		t.Error("renamed over a non-empty directory")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".servercert-*"))
	if len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

func TestAccountKey(t *testing.T) {
	skipOnWindows(t)
	badDER := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("nope")})
	for name, tc := range map[string]struct {
		file []byte
		mode os.FileMode
		want string
	}{
		"not PEM":       {[]byte("text"), 0o600, "not PEM"},
		"bad key":       {badDER, 0o600, "account key"},
		"readable":      {pemKey(newKey()), 0o644, "account key"},
		"a good one":    {pemKey(newKey()), 0o600, ""},
		"no key at all": {nil, 0, ""},
	} {
		files := map[string][]byte{}
		if tc.file != nil {
			files[accountKeyFile] = tc.file
		}
		_, _, err := newDNS(t, cacheWith(t, files, tc.mode), nil)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// A key that cannot be stored.
	is := &dnsIssuer{dir: filepath.Join(t.TempDir(), "nope")}
	if _, err := is.accountKey(); err == nil || !strings.Contains(err.Error(), "account key") {
		t.Errorf("unwritable: %v", err)
	}
}

func TestLoadCachedCertificate(t *testing.T) {
	skipOnWindows(t)
	now := time.Now()
	good := selfSignedPEM(t, []string{domain}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	for name, tc := range map[string]struct {
		pem     []byte
		mode    os.FileMode
		served  bool
		told    int
		wantErr bool
	}{
		"good":        {good, 0o600, true, 0, false},
		"expired":     {selfSignedPEM(t, []string{domain}, now.Add(-48*time.Hour), now.Add(-time.Hour)), 0o600, false, 0, false},
		"other names": {selfSignedPEM(t, []string{"x." + domain}, now.Add(-time.Hour), now.Add(time.Hour)), 0o600, false, 0, false},
		"garbage":     {[]byte("garbage"), 0o600, false, 1, false},
		"readable":    {good, 0o644, false, 0, true},
	} {
		s, got, err := newDNS(t, cacheWith(t, map[string][]byte{certFile: tc.pem}, tc.mode), nil)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if err == nil && ((s.dns.cur != nil) != tc.served || len(got.get()) != tc.told) {
			t.Errorf("%s: served %v, told %v", name, s.dns.cur != nil, got.get())
		}
	}
}

func TestDNSNewRefuses(t *testing.T) {
	skipOnWindows(t)
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, nil, 0o600)
	if _, _, err := newDNS(t, file, nil); err == nil {
		t.Error("a cache that is a file")
	}
	if _, _, err := newDNS(t, cacheWith(t, nil, 0), func(a *ACME) {
		a.DNS = &DNS{CredentialsFile: filepath.Join(t.TempDir(), "none"),
			Provider: func([]byte) (DNSSolver, error) { return &txtZone{}, nil }}
	}); err == nil {
		t.Error("a missing credentials file")
	}
	if _, _, err := newDNS(t, cacheWith(t, nil, 0), func(a *ACME) {
		a.DNS = &DNS{CredentialsFile: file, Provider: func([]byte) (DNSSolver, error) { return nil, nil }}
	}); err == nil || !strings.Contains(err.Error(), "no solver") {
		t.Errorf("a provider with no solver: %v", err)
	}

	key := filepath.Join(t.TempDir(), "eab")
	os.WriteFile(key, []byte("c2VjcmV0LWhtYWM"), 0o600)
	s, _, err := newDNS(t, cacheWith(t, nil, 0), func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", key })
	if err != nil || s.dns.eab == nil || s.dns.eab.KID != "kid" {
		t.Errorf("EAB: %v", err)
	}
	if _, _, err := newDNS(t, cacheWith(t, nil, 0), func(a *ACME) {
		a.EABKeyID, a.EABHMACKeyFile = "kid", filepath.Join(t.TempDir(), "none")
	}); err == nil {
		t.Error("a missing EAB key file")
	}
	if err := (Config{ACME: &ACME{Domains: []string{domain}, CacheDir: "/x", DNS: &DNS{Solver: &txtZone{}, Timeout: -1}}}).Check(); err == nil {
		t.Error("a negative timeout")
	}
}

// TestRenewalFailureKeepsServing: a cached certificate that is due is served
// at once; the renewal runs in the background, fails against a CA that is not
// there, is reported, and is not retried within retryAfter.
func TestRenewalFailureKeepsServing(t *testing.T) {
	skipOnWindows(t)
	now := time.Now()
	due := selfSignedPEM(t, []string{domain}, now.Add(-85*24*time.Hour), now.Add(5*24*time.Hour))
	s, got, err := newDNS(t, cacheWith(t, map[string][]byte{certFile: due}, 0o600), nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.getCertificate(&tls.ClientHelloInfo{ServerName: domain})
	if err != nil || c == nil {
		t.Fatalf("a due certificate was not served: %v", err)
	}
	for i := 0; i < 500 && len(got.get()) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if len(got.get()) == 0 {
		t.Fatal("the failed renewal was not reported")
	}
	// Within retryAfter: no new attempt, the failure is the answer, and the
	// certificate in hand still serves.
	n := len(got.get())
	if err := s.Prefetch(context.Background()); err == nil {
		t.Error("Prefetch hid the failed renewal")
	}
	if c2, err := s.getCertificate(&tls.ClientHelloInfo{ServerName: domain}); err != nil || c2 != c {
		t.Errorf("the old certificate stopped serving: %v", err)
	}
	if len(got.get()) < n {
		t.Error("reports vanished")
	}
	// A certificate that is not due is not renewed, and Close ends Prefetch.
	if _, err := s.dns.issue(context.Background()); err == nil {
		t.Error("issue within the backoff succeeded")
	}
	s.dns.mu.Lock()
	s.dns.cur = nil
	s.dns.mu.Unlock()
	if _, err := s.getCertificate(&tls.ClientHelloInfo{ServerName: domain}); err == nil {
		t.Error("a first issuance against a dead CA succeeded")
	}
	s.Close()
	if err := s.Prefetch(context.Background()); err != nil {
		t.Errorf("Prefetch after Close: %v", err)
	}
}

func TestFreshCertificateIsNotRenewed(t *testing.T) {
	skipOnWindows(t)
	now := time.Now()
	fresh := selfSignedPEM(t, []string{domain}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	s, got, err := newDNS(t, cacheWith(t, map[string][]byte{certFile: fresh}, 0o600), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Prefetch(context.Background()); err != nil { // nothing to do: no CA is asked
		t.Fatal(err)
	}
	c, err := s.dns.issue(context.Background()) // as a handshake that waited for another would
	if err != nil || c != s.dns.cur {
		t.Fatalf("issue: %v", err)
	}
	if e := got.get(); len(e) != 0 {
		t.Errorf("OnError told %v", e)
	}
	// No SNI: the certificate, as with autocert.
	if c, err := s.getCertificate(&tls.ClientHelloInfo{}); err != nil || c == nil {
		t.Errorf("no SNI: %v", err)
	}
}

func TestPropagateWaits(t *testing.T) {
	is := &dnsIssuer{a: &ACME{DNS: &DNS{PropagationWait: time.Hour}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := is.propagate(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled during the wait: %v", err)
	}
	old := defaultPropagationWait
	defaultPropagationWait = time.Millisecond
	defer func() { defaultPropagationWait = old }()
	is.a.DNS.PropagationWait = 0
	if err := is.propagate(context.Background(), nil); err != nil {
		t.Errorf("default wait: %v", err)
	}
}

func TestPresentWithoutDNS01(t *testing.T) {
	st := &orderState{is: &dnsIssuer{}}
	z := &acme.Authorization{Identifier: acme.AuthzID{Type: "dns", Value: "x.example.org"},
		Challenges: []*acme.Challenge{{Type: "http-01"}}}
	if err := st.present(context.Background(), z); err == nil || !strings.Contains(err.Error(), "no dns-01") {
		t.Errorf("err %v", err)
	}
}

// TestPebbleDNS01Authorized: the CA already holds a valid authorization (the
// account proved the name before), so the second order, with the certificate
// gone from the cache, publishes nothing.
func TestPebbleDNS01Authorized(t *testing.T) {
	z := newTXTZone(t)
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "100", z.addr)
	cache := filepath.Join(t.TempDir(), "cache")
	first, _ := dnsSource(t, p, z, cache, []string{domain})
	ln1, _ := freePort(t)
	issued(t, serveOn(t, ln1, first.TLSConfig()), p)
	if err := os.Remove(filepath.Join(cache, certFile)); err != nil {
		t.Fatal(err)
	}

	z.mu.Lock()
	z.events = nil
	z.mu.Unlock()
	second, got := dnsSource(t, p, z, cache, []string{domain})
	ln2, _ := freePort(t)
	issued(t, serveOn(t, ln2, second.TLSConfig()), p)
	if len(z.events) != 0 || len(got.get()) != 0 {
		t.Errorf("a valid authorization was proved again: %v %v", z.events, got.get())
	}
	// Prefetch twice, then no SNI.
	if err := second.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if certs := dialNoSNI(t, serveOn(t, ln2, second.TLSConfig())); len(certs) == 0 {
		t.Error("no certificate without SNI")
	}
}

// TestPebbleDNS01CleanUpFails: a record that cannot be removed does not undo
// the certificate, and is reported.
func TestPebbleDNS01CleanUpFails(t *testing.T) {
	z := newTXTZone(t)
	z.failClean = true
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	s, got := dnsSource(t, p, z, filepath.Join(t.TempDir(), "cache"), []string{domain})
	ln, _ := freePort(t)
	issued(t, serveOn(t, ln, s.TLSConfig()), p)
	e := got.get()
	if len(e) != 1 || !strings.Contains(e[0].Error(), "removing _acme-challenge") {
		t.Errorf("OnError told %v", e)
	}
}

// TestPebbleDNS01CacheNotWritable: the certificate is issued and served even
// when it cannot be kept; the failure to keep it is reported.
func TestPebbleDNS01CacheNotWritable(t *testing.T) {
	z := newTXTZone(t)
	p := startPebbleDNS(t, closedPort(t), closedPort(t), nil, "0", z.addr)
	cache := filepath.Join(t.TempDir(), "cache")
	s, got := dnsSource(t, p, z, cache, []string{domain})
	// The certificate's name taken by a non-empty directory: the rename fails.
	if err := os.MkdirAll(filepath.Join(cache, certFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, _ := freePort(t)
	issued(t, serveOn(t, ln, s.TLSConfig()), p)
	e := got.get()
	if len(e) != 1 || !strings.Contains(e[0].Error(), "caching the certificate") {
		t.Errorf("OnError told %v", e)
	}
}
