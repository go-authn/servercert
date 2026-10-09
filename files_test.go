// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) advance(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

// fileServer starts a Source on a fresh pair with an injected clock and
// serves it; it returns everything a test pokes at.
func fileServer(t *testing.T) (ca *testCA, dir, addr string, clk *clock, got *errs, s *Source) {
	t.Helper()
	ca = newTestCA(t)
	dir = t.TempDir()
	cf, kf := ca.pair(t, dir, "files.test", 1)
	got = &errs{}
	s, err := New(Config{CertFile: cf, KeyFile: kf, OnError: got.add})
	if err != nil {
		t.Fatal(err)
	}
	clk = &clock{now: time.Now()}
	s.files.now = clk.Now
	return ca, dir, serve(t, s.TLSConfig()), clk, got, s
}

func serial(t *testing.T, addr string, ca *testCA) int64 {
	t.Helper()
	leaf, err := dial(addr, "files.test", ca.pool)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return leaf.SerialNumber.Int64()
}

func TestFilesServeAndReloadOnChange(t *testing.T) {
	ca, dir, addr, clk, got, _ := fileServer(t)
	if n := serial(t, addr, ca); n != 1 {
		t.Fatalf("serving serial %d, want 1", n)
	}

	ca.pair(t, dir, "files.test", 2)
	// Within the recheck period the files are not looked at: still 1.
	clk.advance(recheck - time.Second)
	if n := serial(t, addr, ca); n != 1 {
		t.Fatalf("re-read before %v elapsed: serial %d", recheck, n)
	}
	clk.advance(time.Second)
	if n := serial(t, addr, ca); n != 2 {
		t.Fatalf("after the change and %v: serial %d, want 2", recheck, n)
	}
	// Unchanged files: nothing re-parsed, nothing reported.
	clk.advance(recheck)
	if n := serial(t, addr, ca); n != 2 {
		t.Fatalf("unchanged: serial %d, want 2", n)
	}
	if e := got.get(); len(e) != 0 {
		t.Fatalf("OnError told %v about healthy files", e)
	}
}

func TestFilesBrokenReplacementKeepsTheOldOne(t *testing.T) {
	ca, dir, addr, clk, got, _ := fileServer(t)
	kf := filepath.Join(dir, "key.pem")

	// A new certificate whose key has not been written yet: mismatched.
	c3, k3 := ca.leaf(t, "files.test", 3)
	write(t, filepath.Join(dir, "cert.pem"), c3)
	clk.advance(recheck)
	if n := serial(t, addr, ca); n != 1 {
		t.Fatalf("mismatched pair: serving serial %d, want the old 1", n)
	}
	e := got.get()
	if len(e) != 1 || !strings.Contains(e[0].Error(), "still serving") {
		t.Fatalf("OnError got %v, want one 'still serving' error", e)
	}
	// Seen again ten seconds later: not news.
	clk.advance(recheck)
	serial(t, addr, ca)
	if e := got.get(); len(e) != 1 {
		t.Fatalf("the same broken pair was reported %d times", len(e))
	}

	// Positive control: the key arrives, the same machinery swaps.
	write(t, kf, k3)
	clk.advance(recheck)
	if n := serial(t, addr, ca); n != 3 {
		t.Fatalf("completed pair: serial %d, want 3", n)
	}

	// Garbage in the certificate file: not PEM at all.
	write(t, filepath.Join(dir, "cert.pem"), []byte("not a certificate\n"))
	clk.advance(recheck)
	if n := serial(t, addr, ca); n != 3 {
		t.Fatalf("garbage: serial %d, want 3", n)
	}
	if e := got.get(); len(e) != 2 {
		t.Fatalf("garbage after recovery reported %d errors in all, want 2", len(e))
	}
}

func TestFilesVanishedKeepsTheOldOne(t *testing.T) {
	ca, dir, addr, clk, got, _ := fileServer(t)
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cpem, _ := os.ReadFile(cf)
	kpem, _ := os.ReadFile(kf)

	for _, gone := range []string{kf, cf} {
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		clk.advance(recheck)
		if n := serial(t, addr, ca); n != 1 {
			t.Fatalf("%s removed: serial %d, want 1", gone, n)
		}
	}
	if e := got.get(); len(e) != 2 {
		t.Fatalf("OnError got %v, want the key then the cert missing", e)
	}

	// Restored as they were: quietly back, and a failure after that is news.
	write(t, cf, cpem)
	write(t, kf, kpem)
	clk.advance(recheck)
	serial(t, addr, ca)
	os.Remove(kf)
	clk.advance(recheck)
	serial(t, addr, ca)
	if e := got.get(); len(e) != 3 {
		t.Fatalf("a failure after recovery was not reported again: %v", e)
	}
}

func TestFilesNewRefuses(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cf, kf := ca.pair(t, dir, "files.test", 1)

	// Positive control: this very pair is accepted.
	if _, err := New(Config{CertFile: cf, KeyFile: kf}); err != nil {
		t.Fatalf("a good pair was refused: %v", err)
	}

	_, otherKey := ca.leaf(t, "files.test", 2)
	mismatched := filepath.Join(dir, "other-key.pem")
	write(t, mismatched, otherKey)
	missing := filepath.Join(dir, "missing.pem")

	for name, c := range map[string]Config{
		"mismatched key":  {CertFile: cf, KeyFile: mismatched},
		"missing cert":    {CertFile: missing, KeyFile: kf},
		"missing key":     {CertFile: cf, KeyFile: missing},
		"key as the cert": {CertFile: kf, KeyFile: kf},
		"fails Check":     {CertFile: "cert.pem", KeyFile: kf},
	} {
		if s, err := New(c); err == nil {
			t.Errorf("%s: New accepted it (%v)", name, s)
		}
	}
}

// TestFilesConcurrent is for -race: many handshakes while the pair changes.
func TestFilesConcurrent(t *testing.T) {
	ca, dir, addr, clk, _, _ := fileServer(t)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				if _, err := dial(addr, "files.test", ca.pool); err != nil {
					t.Error(err)
					return
				}
				clk.advance(recheck)
			}
		}()
		if i%2 == 0 {
			ca.pair(t, dir, "files.test", int64(10+i))
		}
	}
	wg.Wait()
}

// Prefetch has nothing to do for files.
func TestPrefetchWithFiles(t *testing.T) {
	cf, kf := newTestCA(t).pair(t, t.TempDir(), "files.example", 1)
	s, err := New(Config{CertFile: cf, KeyFile: kf})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Prefetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}
