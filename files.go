// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// recheck is how often, at most, the file pair is looked at again.
const recheck = 10 * time.Second

// fileSource serves a certificate and key read from two files, and re-reads
// them when their CONTENTS change. Contents rather than modification times:
// a replacement written within the file system's timestamp granularity, or
// copied with its old time preserved, has the same mtime and is a different
// certificate. Two small files every ten seconds cost nothing.
type fileSource struct {
	certFile, keyFile string
	now               func() time.Time
	report            func(error)

	mu        sync.Mutex
	cur       *tls.Certificate
	curPEM    [2][]byte // what cur was parsed from
	badPEM    [2][]byte // the last pair that failed to parse: not parsed again
	badErr    string    // the last failure reported
	lastCheck time.Time
}

func newFileSource(certFile, keyFile string, now func() time.Time, report func(error)) (*fileSource, error) {
	f := &fileSource{certFile: certFile, keyFile: keyFile, now: now, report: report}
	pem, err := f.read()
	if err != nil {
		return nil, err
	}
	cert, err := parse(pem, certFile)
	if err != nil {
		return nil, err
	}
	f.cur, f.curPEM, f.lastCheck = cert, pem, now()
	return f, nil
}

func (f *fileSource) read() ([2][]byte, error) {
	c, err := os.ReadFile(f.certFile)
	if err != nil {
		return [2][]byte{}, fmt.Errorf("servercert: %w", err)
	}
	k, err := os.ReadFile(f.keyFile)
	if err != nil {
		return [2][]byte{}, fmt.Errorf("servercert: %w", err)
	}
	return [2][]byte{c, k}, nil
}

// parse loads the pair; tls.X509KeyPair also refuses a key that does not
// belong to the leaf certificate.
func parse(pem [2][]byte, certFile string) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(pem[0], pem[1])
	if err != nil {
		return nil, fmt.Errorf("servercert: %s: %w", certFile, err)
	}
	return &cert, nil
}

func samePair(a, b [2][]byte) bool {
	return bytes.Equal(a[0], b[0]) && bytes.Equal(a[1], b[1])
}

// get returns the certificate to serve. At most one caller per recheck
// period reads and parses the files, and it does so WITHOUT the lock: every
// other handshake meanwhile gets the current certificate at once.
func (f *fileSource) get() *tls.Certificate {
	f.mu.Lock()
	cur := f.cur
	now := f.now()
	if now.Sub(f.lastCheck) < recheck {
		f.mu.Unlock()
		return cur
	}
	f.lastCheck = now
	curPEM, badPEM := f.curPEM, f.badPEM
	f.mu.Unlock()

	pem, err := f.read()
	if err != nil {
		f.fail(err, [2][]byte{})
		return cur
	}
	if samePair(pem, curPEM) {
		// Back to what is served: whatever failed before is over, and the
		// same failure coming back is news again.
		f.mu.Lock()
		f.badPEM, f.badErr = [2][]byte{}, ""
		f.mu.Unlock()
		return cur
	}
	if samePair(pem, badPEM) {
		return cur
	}
	cert, err := parse(pem, f.certFile)
	if err != nil {
		f.fail(err, pem)
		return cur
	}
	f.mu.Lock()
	f.cur, f.curPEM, f.badPEM, f.badErr = cert, pem, [2][]byte{}, ""
	f.mu.Unlock()
	return cert
}

// fail reports err, once: the same failure seen again ten seconds later is
// not news, and a handshake per second would otherwise repeat it forever.
func (f *fileSource) fail(err error, pem [2][]byte) {
	f.mu.Lock()
	repeat := err.Error() == f.badErr
	f.badPEM, f.badErr = pem, err.Error()
	f.mu.Unlock()
	if !repeat {
		f.report(fmt.Errorf("%w; still serving the certificate read before", err))
	}
}
