// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

// Config says where the certificate comes from: a pair of files, or ACME.
// Exactly one of the two is given.
type Config struct {
	// CertFile and KeyFile are PEM files: the certificate chain, leaf first,
	// and its private key. Both absolute. They are re-read when they change
	// (see [Source.TLSConfig]).
	CertFile, KeyFile string

	// ACME obtains and renews the certificate from a CA instead.
	ACME *ACME

	// OnError, if set, is told about what the source could not do but
	// survived: a changed certificate pair that does not parse or whose key
	// does not match (the previous pair keeps being served), or an ACME
	// issuance that failed for one of the configured domains. It is called
	// from inside a TLS handshake, so it must not block.
	OnError func(error)
}

// ACME obtains the certificate from an ACME CA (RFC 8555) through
// golang.org/x/crypto/acme/autocert.
type ACME struct {
	// DirectoryURL is the CA's ACME directory, https only (RFC 8555 §6.1).
	// Empty means Let's Encrypt production, [acme.LetsEncryptURL].
	// For GÉANT TCS it is https://acme.harica.gr/<alias>/directory.
	DirectoryURL string

	// Email is the account's contact address; optional.
	Email string

	// Domains are the names a certificate may be requested for: the host
	// whitelist. Required. No IP address and no wildcard: autocert can do
	// neither (it validates with tls-alpn-01 or http-01, and a wildcard needs
	// dns-01).
	Domains []string

	// CacheDir holds the account key and the certificates, which are
	// private keys. Required and absolute. Created 0700 if missing; one that
	// exists and is accessible by group or others is refused (not checked on
	// Windows, where mode bits do not describe access).
	CacheDir string

	// EABKeyID and EABHMACKeyFile are the External Account Binding (RFC
	// 8555 §7.3.4) a CA such as HARICA, ZeroSSL or Sectigo requires to tie
	// the ACME account to a customer account. Both or neither. The file
	// holds the HMAC key as the CA hands it out, base64url; the key is a
	// secret, which is why it is a file and never a value in the config.
	EABKeyID       string
	EABHMACKeyFile string

	// HTTPChallenge also answers http-01 (RFC 8555 §8.3) when tls-alpn-01
	// fails. The caller must then serve [Source.HTTPHandler] on port 80.
	HTTPChallenge bool

	// HTTPClient talks to the CA. Nil means http.DefaultClient. Set it to
	// trust a private CA's directory certificate, or to go through a proxy.
	// It is copied, not modified: the copy's transport is wrapped to work
	// around golang/go#77704 (see the package documentation).
	HTTPClient *http.Client
}

// Check refuses a Config that cannot work, touching nothing: no file is read
// and no directory created.
func (c Config) Check() error {
	files := c.CertFile != "" || c.KeyFile != ""
	switch {
	case files && c.ACME != nil:
		return errors.New("servercert: both a certificate file pair and ACME are configured; choose one")
	case !files && c.ACME == nil:
		return errors.New("servercert: no certificate source: set CertFile and KeyFile, or ACME")
	case files:
		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("servercert: CertFile and KeyFile go together; one of them is empty")
		}
		if err := absolute("CertFile", c.CertFile); err != nil {
			return err
		}
		return absolute("KeyFile", c.KeyFile)
	}
	return c.ACME.check()
}

func (a *ACME) check() error {
	if len(a.Domains) == 0 {
		return errors.New("servercert: ACME needs at least one domain")
	}
	for _, d := range a.Domains {
		if err := checkDomain(d); err != nil {
			return err
		}
	}
	if a.CacheDir == "" {
		return errors.New("servercert: ACME needs a CacheDir: without one every restart asks the CA again, and rate limits follow")
	}
	if err := absolute("ACME.CacheDir", a.CacheDir); err != nil {
		return err
	}
	if (a.EABKeyID == "") != (a.EABHMACKeyFile == "") {
		return errors.New("servercert: EABKeyID and EABHMACKeyFile go together; one of them is empty")
	}
	if a.EABHMACKeyFile != "" {
		if err := absolute("ACME.EABHMACKeyFile", a.EABHMACKeyFile); err != nil {
			return err
		}
	}
	if a.DirectoryURL != "" {
		u, err := url.Parse(a.DirectoryURL)
		if err != nil {
			return fmt.Errorf("servercert: ACME.DirectoryURL: %w", err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("servercert: ACME.DirectoryURL %q is not an https URL (RFC 8555 §6.1)", a.DirectoryURL)
		}
	}
	return nil
}

func checkDomain(d string) error {
	switch {
	case d == "":
		return errors.New("servercert: ACME.Domains holds an empty name")
	case net.ParseIP(d) != nil:
		return fmt.Errorf("servercert: ACME domain %q is an IP address; autocert issues only for DNS names", d)
	case strings.Contains(d, "*"):
		return fmt.Errorf("servercert: ACME domain %q is a wildcard; that needs dns-01, which autocert does not do", d)
	case strings.HasSuffix(d, "."):
		return fmt.Errorf("servercert: ACME domain %q ends with a dot", d)
	case !strings.Contains(d, "."):
		// autocert refuses such a name at every handshake ("server name
		// component count invalid"); say so now instead.
		return fmt.Errorf("servercert: ACME domain %q has a single label; autocert refuses those", d)
	}
	// autocert.HostWhitelist silently DROPS a name idna refuses, which
	// would leave a configured domain that can never get a certificate.
	if _, err := idna.Lookup.ToASCII(d); err != nil {
		return fmt.Errorf("servercert: ACME domain %q: %w", d, err)
	}
	return nil
}

func absolute(field, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("servercert: %s %q is not an absolute path", field, path)
	}
	return nil
}

// Source serves the server certificate. It is safe for concurrent use.
type Source struct {
	files   *fileSource
	mgr     *autocert.Manager
	domains []string // ASCII, lower case: what OnError is told about
	http01  bool
	onError func(error)
	closed  atomic.Bool
}

// errClosed is what a handshake gets after Close.
var errClosed = errors.New("servercert: source is closed")

// New checks c and prepares the source. With files, the pair is read now and
// a pair that cannot be read, does not parse, or whose key does not match
// the certificate is an error now rather than at the first handshake. With
// ACME, the EAB key file is read and decoded and the cache directory created
// (0700) or checked; no request goes to the CA until a client connects.
func New(c Config) (*Source, error) {
	if err := c.Check(); err != nil {
		return nil, err
	}
	s := &Source{onError: c.OnError}
	if c.ACME == nil {
		f, err := newFileSource(c.CertFile, c.KeyFile, time.Now, s.report)
		if err != nil {
			return nil, err
		}
		s.files = f
		return s, nil
	}
	m, err := newManager(c.ACME)
	if err != nil {
		return nil, err
	}
	s.mgr = m
	s.http01 = c.ACME.HTTPChallenge
	for _, d := range c.ACME.Domains {
		a, _ := idna.Lookup.ToASCII(d) // Check refused the names it cannot convert
		s.domains = append(s.domains, strings.ToLower(a))
	}
	return s, nil
}

func (s *Source) report(err error) {
	if s.onError != nil {
		s.onError(err)
	}
}

// TLSConfig returns a new tls.Config serving this source's certificate, with
// MinVersion TLS 1.2.
//
// With files, the pair is checked for change at most once every 10 seconds,
// during a handshake; a changed pair that fails to load leaves the previous
// one in service and goes to Config.OnError.
//
// With ACME, the certificate is obtained at the first handshake whose SNI
// names one of the domains, and renewed by autocert before it expires. A
// client that connects by IP address sends no SNI and gets no certificate.
// NextProtos then holds "acme-tls/1", the protocol of the tls-alpn-01
// challenge (RFC 8737): APPEND your own protocols to it, never replace it,
// or the CA's validation fails. Append them, too: a Go TLS server that
// advertises ALPN protocols refuses a client whose offer shares none of
// them, so an NFS server must add "sunrpc" (RFC 9289). net/http's ServeTLS
// adds "http/1.1" (and "h2") by itself.
func (s *Source) TLSConfig() *tls.Config {
	tc := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: s.getCertificate,
	}
	if s.mgr != nil {
		tc.NextProtos = []string{acme.ALPNProto}
	}
	return tc
}

func (s *Source) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s.closed.Load() {
		return nil, errClosed
	}
	if s.files != nil {
		return s.files.get(), nil
	}
	cert, err := s.mgr.GetCertificate(hello)
	// A scanner asking for a name we do not serve is its own problem; a
	// failure for one of OUR names is ours, and nothing else would say so.
	if err != nil && slices.Contains(s.domains, strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))) {
		s.report(fmt.Errorf("servercert: certificate for %s: %w", hello.ServerName, err))
	}
	return cert, err
}

// HTTPHandler answers the http-01 challenge under /.well-known/acme-challenge/
// and hands every other request to fallback; a nil fallback redirects to
// https. It is meaningful only with ACME and HTTPChallenge, and must then be
// served on port 80. Otherwise it is fallback itself, or a 404 handler when
// fallback is nil.
func (s *Source) HTTPHandler(fallback http.Handler) http.Handler {
	if s.http01 {
		h := s.mgr.HTTPHandler(fallback)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// autocert checks the Host header against the whitelist as it
			// is, port included. A CA validating on port 80 sends none,
			// but one told to use another port (a test CA, a CA behind a
			// port mapping) does, and would be refused with 403.
			if host, _, err := net.SplitHostPort(r.Host); err == nil {
				r = r.Clone(r.Context())
				r.Host = host
			}
			h.ServeHTTP(w, r)
		})
	}
	if fallback == nil {
		return http.NotFoundHandler()
	}
	return fallback
}

// Close stops serving: every handshake after it fails. Certificates already
// in the cache directory stay there. It always returns nil.
func (s *Source) Close() error {
	s.closed.Store(true)
	return nil
}
