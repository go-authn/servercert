// SPDX-License-Identifier: BSD-3-Clause

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
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// testCA is a throwaway CA; a certificate it signs is checked by crypto/tls's
// own verifier in a real handshake, not by anything this package wrote.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "servercert test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leaf returns PEM certificate and PEM key for name, with serial n so two
// leaves can be told apart.
func (ca *testCA) leaf(t *testing.T, name string, n int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(n),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// pair writes a leaf to dir/cert.pem and dir/key.pem and returns the paths.
func (ca *testCA) pair(t *testing.T, dir, name string, n int64) (string, string) {
	t.Helper()
	c, k := ca.leaf(t, name, n)
	cf, kf := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write(t, cf, c)
	write(t, kf, k)
	return cf, kf
}

// serve accepts TLS connections on a loopback port with tc and completes
// each handshake; it returns the address.
func serve(t *testing.T, tc *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return serveOn(t, ln, tc)
}

func serveOn(t *testing.T, ln net.Listener, tc *tls.Config) string {
	t.Helper()
	var wg sync.WaitGroup
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	tl := tls.NewListener(ln, tc)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.SetDeadline(time.Now().Add(2 * time.Minute))
				_ = c.(*tls.Conn).Handshake()
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

// dial handshakes with addr as name, verifying against roots, and returns
// the leaf the server presented.
func dial(addr, name string, roots *x509.CertPool) (*x509.Certificate, error) {
	d := &net.Dialer{Timeout: 2 * time.Minute}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: name, RootCAs: roots})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0], nil
}

// errs collects what OnError is told.
type errs struct {
	mu   sync.Mutex
	list []error
}

func (e *errs) add(err error) { e.mu.Lock(); e.list = append(e.list, err); e.mu.Unlock() }

func (e *errs) get() []error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]error(nil), e.list...)
}
