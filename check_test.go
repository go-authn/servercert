// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"
)

func TestCheck(t *testing.T) {
	abs := t.TempDir()
	cf, kf := filepath.Join(abs, "c.pem"), filepath.Join(abs, "k.pem")
	good := func() *ACME {
		return &ACME{Domains: []string{"a.example.org", "bücher.example"}, CacheDir: filepath.Join(abs, "cache")}
	}

	// Positive controls: each refusal below is one change away from these.
	for name, c := range map[string]Config{
		"files":        {CertFile: cf, KeyFile: kf},
		"acme":         {ACME: good()},
		"acme+eab":     {ACME: func() *ACME { a := good(); a.EABKeyID, a.EABHMACKeyFile = "kid", kf; return a }()},
		"acme+dirURL":  {ACME: func() *ACME { a := good(); a.DirectoryURL = "https://acme.harica.gr/x/directory"; return a }()},
		"acme+http-01": {ACME: func() *ACME { a := good(); a.HTTPChallenge = true; return a }()},
	} {
		if err := c.Check(); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}

	with := func(f func(*ACME)) Config { a := good(); f(a); return Config{ACME: a} }
	for name, tc := range map[string]struct {
		c    Config
		want string
	}{
		"nothing":            {Config{}, "no certificate source"},
		"both":               {Config{CertFile: cf, KeyFile: kf, ACME: good()}, "both"},
		"cert only":          {Config{CertFile: cf}, "go together"},
		"key only":           {Config{KeyFile: kf}, "go together"},
		"relative cert":      {Config{CertFile: "c.pem", KeyFile: kf}, "CertFile"},
		"relative key":       {Config{CertFile: cf, KeyFile: "k.pem"}, "KeyFile"},
		"no domains":         {with(func(a *ACME) { a.Domains = nil }), "at least one domain"},
		"empty domain":       {with(func(a *ACME) { a.Domains = []string{""} }), "empty name"},
		"IPv4":               {with(func(a *ACME) { a.Domains = []string{"192.0.2.1"} }), "IP address"},
		"IPv6":               {with(func(a *ACME) { a.Domains = []string{"2001:db8::1"} }), "IP address"},
		"wildcard":           {with(func(a *ACME) { a.Domains = []string{"*.example.org"} }), "wildcard"},
		"trailing dot":       {with(func(a *ACME) { a.Domains = []string{"a.example.org."} }), "ends with a dot"},
		"single label":       {with(func(a *ACME) { a.Domains = []string{"fileserver"} }), "single label"},
		"not a host name":    {with(func(a *ACME) { a.Domains = []string{"a_b/c.example"} }), "a_b/c.example"},
		"no cache":           {with(func(a *ACME) { a.CacheDir = "" }), "CacheDir"},
		"relative cache":     {with(func(a *ACME) { a.CacheDir = "cache" }), "not an absolute path"},
		"EAB id only":        {with(func(a *ACME) { a.EABKeyID = "kid" }), "go together"},
		"EAB file only":      {with(func(a *ACME) { a.EABHMACKeyFile = kf }), "go together"},
		"EAB relative":       {with(func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", "hmac" }), "EABHMACKeyFile"},
		"directory http":     {with(func(a *ACME) { a.DirectoryURL = "http://acme.example/dir" }), "not an https URL"},
		"directory no host":  {with(func(a *ACME) { a.DirectoryURL = "https:///dir" }), "not an https URL"},
		"directory unparsed": {with(func(a *ACME) { a.DirectoryURL = "https://a b\x7f/" }), "DirectoryURL"},
	} {
		err := tc.c.Check()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want an error containing %q", name, err, tc.want)
		}
	}
}

// TestCheckTouchesNothing: Check must not create the cache directory.
func TestCheckTouchesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := (Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: dir}}).Check(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Check created %s (stat: %v)", dir, err)
	}
	// Positive control: New does create it, 0700.
	s, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		t.Fatalf("New did not create the cache directory: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
		t.Fatalf("cache directory is %v, want 0700", fi.Mode().Perm())
	}
}

func TestReadEABKey(t *testing.T) {
	dir := t.TempDir()
	key := []byte{0xfb, 0xff, 0x3e, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29}
	for name, text := range map[string]string{
		"base64url raw":    base64.RawURLEncoding.EncodeToString(key),
		"base64url padded": base64.URLEncoding.EncodeToString(key) + "\n",
		"std base64":       "  " + base64.StdEncoding.EncodeToString(key) + "\r\n",
	} {
		p := filepath.Join(dir, "k")
		write(t, p, []byte(text))
		got, err := readEABKey(p)
		if err != nil || string(got) != string(key) {
			t.Errorf("%s: got %x, %v", name, got, err)
		}
	}
	secret := "not*base64!secret"
	for name, text := range map[string]string{"empty": " \n", "garbage": secret} {
		p := filepath.Join(dir, "k")
		write(t, p, []byte(text))
		_, err := readEABKey(p)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error quotes the key file's contents: %v", name, err)
		}
	}
	if _, err := readEABKey(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing key file was accepted")
	}
}

func TestNewACMERefuses(t *testing.T) {
	dir := t.TempDir()
	notDir := filepath.Join(dir, "file")
	write(t, notDir, []byte("x"))
	keyFile := filepath.Join(dir, "hmac")
	write(t, keyFile, []byte(base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))))

	acmeWith := func(f func(*ACME)) Config {
		a := &ACME{Domains: []string{"a.example.org"}, CacheDir: filepath.Join(dir, "ok")}
		f(a)
		return Config{ACME: a}
	}
	// Positive control.
	if _, err := New(acmeWith(func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", keyFile })); err != nil {
		t.Fatalf("a good ACME config was refused: %v", err)
	}
	for name, c := range map[string]Config{
		"cache is a file":        acmeWith(func(a *ACME) { a.CacheDir = notDir }),
		"cache under a file":     acmeWith(func(a *ACME) { a.CacheDir = filepath.Join(notDir, "sub") }),
		"EAB key file missing":   acmeWith(func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", filepath.Join(dir, "none") }),
		"fails Check":            acmeWith(func(a *ACME) { a.Domains = nil }),
		"EAB key file not b64":   acmeWith(func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", notDir }),
		"EAB key file directory": acmeWith(func(a *ACME) { a.EABKeyID, a.EABHMACKeyFile = "kid", dir }),
	} {
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCacheDirOpenToOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not describe access on Windows; checkPrivate accepts every directory there")
	}
	for _, mode := range []os.FileMode{0o750, 0o705, 0o777} {
		dir := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		_, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: dir}})
		if err == nil || !strings.Contains(err.Error(), "group or others") {
			t.Errorf("mode %v: got %v, want a refusal", mode, err)
		}
		// Positive control: the same directory, tightened, is accepted.
		os.Chmod(dir, 0o700)
		if _, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: dir}}); err != nil {
			t.Errorf("mode 0700 after %v: refused: %v", mode, err)
		}
	}
}

func TestCacheDirUnstattable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a directory without search permission cannot be made with mode bits on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads through a mode-000 directory")
	}
	parent := filepath.Join(t.TempDir(), "locked")
	os.Mkdir(parent, 0o700)
	os.Chmod(parent, 0)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	_, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: filepath.Join(parent, "cache")}})
	if err == nil || !strings.Contains(err.Error(), "cache directory") {
		t.Fatalf("got %v, want the stat failure", err)
	}

	// A parent that can be searched but not written: the stat says "does
	// not exist" and the creation fails.
	readOnly := filepath.Join(t.TempDir(), "ro")
	os.Mkdir(readOnly, 0o500)
	t.Cleanup(func() { os.Chmod(readOnly, 0o700) })
	_, err = New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: filepath.Join(readOnly, "cache")}})
	if err == nil || !strings.Contains(err.Error(), "cache directory") {
		t.Fatalf("got %v, want the creation failure", err)
	}
}

func TestTLSConfigAndHandler(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cf, kf := ca.pair(t, dir, "files.test", 1)
	files, err := New(Config{CertFile: cf, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	tc := files.TLSConfig()
	if tc.MinVersion != tls.VersionTLS12 || len(tc.NextProtos) != 0 {
		t.Errorf("files TLSConfig: MinVersion %x NextProtos %v", tc.MinVersion, tc.NextProtos)
	}
	if tc == files.TLSConfig() {
		t.Error("TLSConfig returned the same *tls.Config twice; a caller appending NextProtos would change the other's")
	}

	a, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: filepath.Join(dir, "c1")}})
	if err != nil {
		t.Fatal(err)
	}
	if p := a.TLSConfig().NextProtos; len(p) != 1 || p[0] != acme.ALPNProto {
		t.Errorf("ACME NextProtos = %v, want [%s]", p, acme.ALPNProto)
	}

	fallback := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(299) })
	h01, err := New(Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: filepath.Join(dir, "c2"), HTTPChallenge: true}})
	if err != nil {
		t.Fatal(err)
	}
	status := func(h http.Handler, target string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", target, nil))
		return rec.Code
	}
	for name, tc := range map[string]struct {
		h    http.Handler
		path string
		want int
	}{
		"files, fallback":               {files.HTTPHandler(fallback), "/", 299},
		"files, nil":                    {files.HTTPHandler(nil), "/", 404},
		"ACME without http-01, nil":     {a.HTTPHandler(nil), "/.well-known/acme-challenge/x", 404},
		"ACME without http-01, fb":      {a.HTTPHandler(fallback), "/", 299},
		"http-01, fallback":             {h01.HTTPHandler(fallback), "/", 299},
		"http-01, nil redirects":        {h01.HTTPHandler(nil), "http://a.example.org/", http.StatusFound},
		"http-01, unknown token":        {h01.HTTPHandler(fallback), "http://a.example.org/.well-known/acme-challenge/x", 404},
		"http-01, not a whitelist name": {h01.HTTPHandler(nil), "http://evil.example/.well-known/acme-challenge/x", http.StatusForbidden},
	} {
		if got := status(tc.h, tc.path); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}

func TestClose(t *testing.T) {
	ca := newTestCA(t)
	cf, kf := ca.pair(t, t.TempDir(), "files.test", 1)
	s, err := New(Config{CertFile: cf, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, s.TLSConfig())
	// Positive control: it serves before Close.
	if _, err := dial(addr, "files.test", ca.pool); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(addr, "files.test", ca.pool); err == nil {
		t.Fatal("a handshake succeeded after Close")
	}
}
