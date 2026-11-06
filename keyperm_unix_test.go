// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package servercert

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Second-pass audit 2026-11. The private key and the EAB HMAC key are secrets
// read from files; the ACME cache directory is refused when group or others
// can reach it, but these two files were read with no permission check.
func TestAKeyFileGroupOrOthersCanReadIsRefused(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cf, kf := ca.pair(t, dir, "perm.test", 1)

	for _, mode := range []os.FileMode{0o600, 0o400} {
		if err := os.Chmod(kf, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{CertFile: cf, KeyFile: kf}); err != nil {
			t.Fatalf("a key file of mode %v was refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		if err := os.Chmod(kf, mode); err != nil {
			t.Fatal(err)
		}
		_, err := New(Config{CertFile: cf, KeyFile: kf})
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("a key file of mode %v: err = %v, want a refusal that says chmod 600", mode, err)
		}
	}
}

// A replacement key written readable is not picked up either: the current
// certificate keeps serving and the error is reported.
func TestAReloadedKeyFileMustBePrivateToo(t *testing.T) {
	ca, dir, _, clk, got, s := fileServer(t)
	cf, kf := ca.pair(t, dir, "files.test", 2)
	if err := os.Chmod(kf, 0o644); err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Hour)
	if _, err := s.TLSConfig().GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	_ = cf
	if len(got.get()) == 0 {
		t.Error("a world-readable replacement key was taken without a word")
	}
}

func TestAnEABKeyFileGroupOrOthersCanReadIsRefused(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/eab"
	if err := os.WriteFile(p, []byte("c2VjcmV0LWhtYWM"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEABKey(p); err != nil {
		t.Fatalf("a private EAB key file was refused: %v", err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readEABKey(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("err = %v, want a refusal that says chmod 600", err)
	}
}
