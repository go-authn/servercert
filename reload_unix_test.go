// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package servercert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Two re-reads must not overlap: one stalled in reading (a FIFO stands in
// for a hung network file system) while a later one reads a newer pair
// would, on finishing last, put back the older certificate.
func TestFilesSlowReloadDoesNotRevert(t *testing.T) {
	ca := newTestCA(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := func(n int64) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(n), Subject: pkix.Name{CommonName: "files.test"},
			DNSNames: []string{"files.test"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	serialOf := func(c *tls.Certificate) int64 {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return leaf.SerialNumber.Int64()
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write(t, cf, certPEM(1))
	write(t, kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}))
	clk := &clock{now: time.Now()}
	f, err := newFileSource(cf, kf, clk.Now, func(error) {})
	if err != nil {
		t.Fatal(err)
	}

	// The certificate file becomes a FIFO: the first re-read blocks in it.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Rename(fifo, cf); err != nil {
		t.Fatal(err)
	}
	clk.advance(recheck)
	first := make(chan int64, 1)
	go func() { first <- serialOf(f.get()) }()

	// Opening the write end without blocking succeeds once the reader is in.
	var w *os.File
	for deadline := time.Now().Add(10 * time.Second); w == nil; {
		w, err = os.OpenFile(cf, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			if time.Now().After(deadline) {
				t.Fatalf("the first re-read never opened the certificate: %v", err)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Meanwhile the pair is replaced by serial 3 and a second re-read is due.
	next := filepath.Join(dir, "next.pem")
	write(t, next, certPEM(3))
	if err := os.Rename(next, cf); err != nil {
		t.Fatal(err)
	}
	clk.advance(recheck)
	second := serialOf(f.get())

	// The first re-read now gets serial 2, older than 3.
	w.Write(certPEM(2))
	w.Close()
	firstGot := <-first
	final := serialOf(f.get())
	t.Logf("second re-read served %d, first %d, then %d", second, firstGot, final)
	if final < second {
		t.Fatalf("serial %d went back to %d: the stalled re-read finished last and won", second, final)
	}
	// And re-reading still works: the next check serves serial 3.
	clk.advance(recheck)
	if n := serialOf(f.get()); n != 3 {
		t.Fatalf("after the stall: serial %d, want 3", n)
	}
}
