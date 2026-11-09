// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// dnsIssuer obtains one certificate for every configured name through
// golang.org/x/crypto/acme with dns-01, keeps it in the cache directory
// (0600), serves it and renews it in the background.
type dnsIssuer struct {
	a       *ACME
	solver  DNSSolver
	domains []string // ASCII, lower case, wildcards as "*.base"
	dir     string
	client  *acme.Client
	eab     *acme.ExternalAccountBinding
	now     func() time.Time
	report  func(error)

	issueMu  sync.Mutex // one issuance at a time
	mu       sync.Mutex // guards what follows
	cur      *tls.Certificate
	failedAt time.Time
	failure  error
}

const (
	// retryAfter is how long after a failed issuance the next handshake waits
	// before it asks the CA again: a CA's failed-validation rate limit is hit
	// by a loop, not by a person.
	retryAfter = time.Minute

	accountKeyFile = "dns01-account.key"
	certFile       = "dns01-certificate.pem"
)

// Defaults, variables so that a test need not wait them out.
var (
	defaultPropagationWait = 10 * time.Second
	defaultOrderTimeout    = 5 * time.Minute
)

func newDNSIssuer(a *ACME, domains []string, report func(error)) (*dnsIssuer, error) {
	if err := cacheDir(a.CacheDir); err != nil {
		return nil, err
	}
	sv, err := a.DNS.solver()
	if err != nil {
		return nil, err
	}
	is := &dnsIssuer{a: a, solver: sv, domains: domains, dir: filepath.Clean(a.CacheDir),
		now: time.Now, report: report}
	key, err := is.accountKey()
	if err != nil {
		return nil, err
	}
	is.client = &acme.Client{Key: key, DirectoryURL: cmp.Or(a.DirectoryURL, acme.LetsEncryptURL),
		HTTPClient: withOrderLocations(a.HTTPClient)}
	if a.EABKeyID != "" {
		k, err := readEABKey(a.EABHMACKeyFile)
		if err != nil {
			return nil, err
		}
		is.eab = &acme.ExternalAccountBinding{KID: a.EABKeyID, Key: k}
	}
	return is, is.load()
}

// must is for what fails only when the system's entropy source does.
func must[T any](v T, err error) T {
	if err != nil {
		panic("servercert: " + err.Error())
	}
	return v
}

// accountKey reads the ACME account key from the cache, or makes and stores
// one (ECDSA P-256, PEM, 0600).
func (is *dnsIssuer) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(is.dir, accountKeyFile)
	raw, err := readSecretFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k := newKey()
		if err := writePrivate(path, pemKey(k)); err != nil {
			return nil, fmt.Errorf("servercert: account key: %w", err)
		}
		return k, nil
	}
	if err != nil {
		return nil, fmt.Errorf("servercert: account key: %w", err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("servercert: account key %s is not PEM", path)
	}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("servercert: account key %s: %w", path, err)
	}
	return k, nil
}

func newKey() *ecdsa.PrivateKey { return must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader)) }

func pemKey(k *ecdsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: must(x509.MarshalECPrivateKey(k))})
}

// writePrivate writes path 0600 (os.CreateTemp's mode) by writing a temporary
// file in the same directory and renaming it over: a reader sees the old file
// or the whole new one.
func writePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".servercert-*")
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	err = errors.Join(werr, f.Close())
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		err = errors.Join(err, os.Remove(f.Name()))
	}
	return err
}

// load takes the cached certificate, if it still covers every configured
// name and has not expired; otherwise there is none, and the first handshake
// (or Prefetch) issues.
func (is *dnsIssuer) load() error {
	raw, err := readSecretFile(filepath.Join(is.dir, certFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("servercert: cached certificate: %w", err)
	}
	cert, err := tls.X509KeyPair(raw, raw) // sets cert.Leaf
	if err != nil {
		is.report(fmt.Errorf("servercert: cached certificate ignored: %w", err))
		return nil
	}
	if is.now().Before(cert.Leaf.NotAfter) && covers(cert.Leaf, is.domains) {
		is.cur = &cert
	}
	return nil
}

// covers says every configured name is a name of the certificate, exactly (a
// wildcard name only by the wildcard).
func covers(leaf *x509.Certificate, domains []string) bool {
	have := map[string]bool{}
	for _, n := range leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	for _, d := range domains {
		if !have[d] {
			return false
		}
	}
	return true
}

// due says the certificate should be renewed: less than a third of its life
// left, and at most 30 days.
func (is *dnsIssuer) due(c *tls.Certificate) bool {
	left := c.Leaf.NotAfter.Sub(is.now())
	life := c.Leaf.NotAfter.Sub(c.Leaf.NotBefore)
	return left < min(30*24*time.Hour, life/3)
}

// serves says whether a client asking for name is one of ours: an exact name,
// or a name one label below a wildcard (RFC 6125 §6.4.3).
func (is *dnsIssuer) serves(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, d := range is.domains {
		if d == name {
			return true
		}
		if base, ok := wildcardBase(d); ok {
			if label, rest, found := strings.Cut(name, "."); found && label != "" && rest == base {
				return true
			}
		}
	}
	return false
}

// get is the GetCertificate of the issuer.
func (is *dnsIssuer) get(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName != "" && !is.serves(hello.ServerName) {
		return nil, fmt.Errorf("servercert: %q is not one of the configured domains", hello.ServerName)
	}
	is.mu.Lock()
	cur := is.cur
	is.mu.Unlock()
	if cur == nil {
		return is.issue(context.Background())
	}
	if is.due(cur) {
		go is.issue(context.Background()) // the certificate in hand keeps serving; failures are reported there
	}
	return cur, nil
}

// ensure issues now when there is no certificate or it is due.
func (is *dnsIssuer) ensure(ctx context.Context) error {
	is.mu.Lock()
	cur := is.cur
	is.mu.Unlock()
	if cur != nil && !is.due(cur) {
		return nil
	}
	_, err := is.issue(ctx)
	return err
}

// issue runs one issuance at a time; a caller that waited for another finds
// its certificate and returns it. A failure is remembered for retryAfter, and
// reported; a renewal that failed leaves the certificate in hand in service.
func (is *dnsIssuer) issue(ctx context.Context) (*tls.Certificate, error) {
	is.issueMu.Lock()
	defer is.issueMu.Unlock()

	is.mu.Lock()
	cur, failedAt, failure := is.cur, is.failedAt, is.failure
	is.mu.Unlock()
	switch {
	case cur != nil && !is.due(cur):
		return cur, nil
	case failure != nil && is.now().Sub(failedAt) < retryAfter:
		return cur, failure
	}

	cert, err := is.obtain(ctx)

	is.mu.Lock()
	defer is.mu.Unlock()
	if err != nil {
		is.failedAt, is.failure = is.now(), err
		is.report(err)
		return is.cur, err
	}
	is.failedAt, is.failure, is.cur = time.Time{}, nil, cert
	return cert, nil
}

// record is one TXT value published at one name.
type record struct{ name, value string }

// each runs f on every element and stops at the first error.
func each[T any](xs []T, f func(T) error) error {
	for _, x := range xs {
		if err := f(x); err != nil {
			return err
		}
	}
	return nil
}

// obtain is one order, RFC 8555 §7.4: account, new-order, an authorization
// per name proved by a TXT record, finalize, download.
func (is *dnsIssuer) obtain(ctx context.Context) (*tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(is.a.DNS.Timeout, defaultOrderTimeout))
	defer cancel()

	var (
		order *acme.Order
		der   [][]byte
		cert  tls.Certificate
		buf   []byte
		key   = newKey()
		st    = &orderState{is: is}
	)
	defer func() {
		// The records come out whatever happened, and even when ctx is done.
		cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer stop()
		for _, r := range st.published {
			if err := is.solver.CleanUp(cctx, r.name, r.value); err != nil {
				is.report(fmt.Errorf("servercert: removing %s: %w", r.name, err))
			}
		}
	}()

	steps := []struct {
		name string
		run  func() error
	}{
		{"account", func() error {
			acct := &acme.Account{ExternalAccountBinding: is.eab}
			if is.a.Email != "" {
				acct.Contact = []string{"mailto:" + is.a.Email}
			}
			_, err := is.client.Register(ctx, acct, acme.AcceptTOS)
			if errors.Is(err, acme.ErrAccountAlreadyExists) {
				return nil
			}
			return err
		}},
		{"new order", func() (err error) {
			order, err = is.client.AuthorizeOrder(ctx, acme.DomainIDs(is.domains...))
			return err
		}},
		{"authorization", func() error {
			return each(order.AuthzURLs, func(u string) error {
				z, err := is.client.GetAuthorization(ctx, u)
				if err != nil || z.Status == acme.StatusValid { // valid already: nothing to prove
					return err
				}
				return st.present(ctx, z)
			})
		}},
		{"propagation", func() error { return is.propagate(ctx, st.published) }},
		{"accepting the challenges", func() error {
			return each(st.chals, func(c *acme.Challenge) error { _, err := is.client.Accept(ctx, c); return err })
		}},
		{"validation", func() error {
			return each(st.authzURIs, func(u string) error { _, err := is.client.WaitAuthorization(ctx, u); return err })
		}},
		{"order", func() (err error) {
			order, err = is.client.WaitOrder(ctx, order.URI)
			return err
		}},
		{"finalize", func() (err error) {
			csr := must(x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: is.domains}, key))
			der, _, err = is.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
			return err
		}},
		{"the CA's certificate", func() (err error) {
			buf = pemKey(key)
			for _, c := range der {
				buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
			}
			cert, err = tls.X509KeyPair(buf, buf) // sets cert.Leaf
			return err
		}},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			return nil, fmt.Errorf("servercert: dns-01 for %s: %s: %w", strings.Join(is.domains, ", "), s.name, err)
		}
	}
	if err := writePrivate(filepath.Join(is.dir, certFile), buf); err != nil {
		is.report(fmt.Errorf("servercert: caching the certificate: %w", err))
	}
	return &cert, nil
}

// orderState is what an order has published so far.
type orderState struct {
	is        *dnsIssuer
	published []record
	chals     []*acme.Challenge
	authzURIs []string
}

// present publishes the TXT record of the dns-01 challenge of a pending
// authorization.
func (st *orderState) present(ctx context.Context, z *acme.Authorization) error {
	var chal *acme.Challenge
	for _, c := range z.Challenges {
		if c.Type == "dns-01" {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("the CA offers no dns-01 challenge for %s", z.Identifier.Value)
	}
	// A wildcard's authorization names the base domain.
	r := record{"_acme-challenge." + z.Identifier.Value + ".", must(st.is.client.DNS01ChallengeRecord(chal.Token))}
	if err := st.is.solver.Present(ctx, r.name, r.value); err != nil {
		return fmt.Errorf("publishing %s: %w", r.name, err)
	}
	st.published = append(st.published, r)
	st.chals, st.authzURIs = append(st.chals, chal), append(st.authzURIs, z.URI)
	return nil
}

// propagate waits until Resolver, when set, answers with every published
// value, then sleeps PropagationWait.
func (is *dnsIssuer) propagate(ctx context.Context, published []record) error {
	d := is.a.DNS
	if d.Resolver != "" {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "tcp", d.Resolver)
		}}
		for _, rec := range published {
			for {
				got, err := r.LookupTXT(ctx, rec.name)
				if err == nil && contains(got, rec.value) {
					break
				}
				select {
				case <-ctx.Done():
					return fmt.Errorf("%s is not visible at %s: %w", rec.name, d.Resolver, ctx.Err())
				case <-time.After(time.Second):
				}
			}
		}
	}
	if wait := cmp.Or(d.PropagationWait, defaultPropagationWait); wait > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil
}

func contains(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}
