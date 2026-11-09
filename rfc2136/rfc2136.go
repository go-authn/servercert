// SPDX-License-Identifier: BSD-3-Clause

// Package rfc2136 publishes the TXT records of an ACME dns-01 challenge
// (RFC 8555 §8.4) into a DNS server that takes dynamic updates (RFC 2136),
// authenticated with a TSIG key (RFC 8945) -- BIND, Knot, PowerDNS and most
// school or campus name servers.
//
// It is a provider for github.com/go-authn/servercert's ACME.DNS, and is a
// module of its own so that the core does not carry a DNS library: *Solver has
// the methods of servercert.DNSSolver, without importing it.
//
//	DNS: &servercert.DNS{
//	    CredentialsFile: "/etc/relay/dns-update.conf", // 0600, see ParseCredentials
//	    Provider: func(b []byte) (servercert.DNSSolver, error) { return rfc2136.New(b) },
//	}
//
// The credentials file holds the server, the zone and the TSIG key, which is
// the secret: it is a file, never an argument, an environment variable or a URL.
package rfc2136

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// maxCredentials bounds the file: nothing real is larger.
const maxCredentials = 4 << 10

// Solver sends DNS UPDATE messages (RFC 2136 §2) signed with TSIG.
type Solver struct {
	// Server is "host:port" of the primary that accepts updates.
	Server string
	// Zone is the zone updated, fully qualified; every record name must be
	// inside it (RFC 2136 §2.3).
	Zone string
	// KeyName and Algorithm and Secret are the TSIG key (RFC 8945). Secret is
	// base64, as BIND's tsig-keygen prints it.
	KeyName, Algorithm, Secret string
	// TTL of the TXT records, in seconds; 0 means 60.
	TTL uint32
	// Timeout of one exchange; 0 means 10 seconds.
	Timeout time.Duration
}

// algorithms are the HMACs accepted: RFC 8945 §6 deprecates hmac-md5 and
// treats hmac-sha1 as legacy, so neither is offered.
var algorithms = map[string]string{
	"hmac-sha256": dns.HmacSHA256,
	"hmac-sha384": dns.HmacSHA384,
	"hmac-sha512": dns.HmacSHA512,
}

// ParseCredentials reads the credentials file:
//
//	# comment
//	server    = 192.0.2.53:53
//	zone      = class.example-school.fr
//	key       = acme-update
//	algorithm = hmac-sha256        (optional; hmac-sha256, -sha384, -sha512)
//	secret    = bWFkZSB1cCBrZXk=   (base64, the TSIG secret)
//
// Every key but algorithm is required and none may repeat; an unknown key is
// an error, so a typo does not silently drop the secret. Errors never quote
// the secret.
func ParseCredentials(b []byte) (*Solver, error) {
	if len(b) > maxCredentials {
		return nil, fmt.Errorf("rfc2136: credentials larger than %d bytes", maxCredentials)
	}
	got := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("rfc2136: credentials line %d: want key = value", n)
		}
		switch k {
		case "server", "zone", "key", "algorithm", "secret":
		default:
			return nil, fmt.Errorf("rfc2136: credentials line %d: unknown key %q", n, k)
		}
		if _, dup := got[k]; dup {
			return nil, fmt.Errorf("rfc2136: credentials line %d: %q given twice", n, k)
		}
		got[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("rfc2136: credentials: %w", err)
	}
	for _, k := range []string{"server", "zone", "key", "secret"} {
		if got[k] == "" {
			return nil, fmt.Errorf("rfc2136: credentials: %q is missing", k)
		}
	}
	alg := got["algorithm"]
	if alg == "" {
		alg = "hmac-sha256"
	}
	if _, ok := algorithms[strings.ToLower(alg)]; !ok {
		return nil, fmt.Errorf("rfc2136: credentials: algorithm %q: want hmac-sha256, hmac-sha384 or hmac-sha512", alg)
	}
	s := &Solver{Server: got["server"], Zone: dns.Fqdn(strings.ToLower(got["zone"])),
		KeyName: dns.Fqdn(strings.ToLower(got["key"])), Algorithm: strings.ToLower(alg), Secret: got["secret"]}
	return s, s.check()
}

// New is ParseCredentials, named for what a Provider calls.
func New(credentials []byte) (*Solver, error) { return ParseCredentials(credentials) }

func (s *Solver) check() error {
	if _, ok := algorithms[s.Algorithm]; !ok {
		return fmt.Errorf("rfc2136: algorithm %q: want hmac-sha256, hmac-sha384 or hmac-sha512", s.Algorithm)
	}
	if raw, err := base64.StdEncoding.DecodeString(s.Secret); err != nil || len(raw) == 0 {
		return errors.New("rfc2136: the TSIG secret is not base64") // not quoted: a secret
	}
	if _, ok := dns.IsDomainName(s.Zone); !ok {
		return fmt.Errorf("rfc2136: zone %q is not a domain name", s.Zone)
	}
	if _, ok := dns.IsDomainName(s.KeyName); !ok {
		return fmt.Errorf("rfc2136: key name %q is not a domain name", s.KeyName)
	}
	if i := strings.LastIndexByte(s.Server, ':'); i <= 0 || i == len(s.Server)-1 {
		return fmt.Errorf("rfc2136: server %q is not host:port", s.Server)
	}
	return nil
}

// Present adds the TXT record (RFC 2136 §2.5.1, "add to an RRset"); other
// values at the name stay.
func (s *Solver) Present(ctx context.Context, name, value string) error {
	return s.update(ctx, name, value, true)
}

// CleanUp deletes that one TXT record (§2.5.4, "delete an RR from an RRset");
// deleting one that is not there is not an error (§3.4.2.4).
func (s *Solver) CleanUp(ctx context.Context, name, value string) error {
	return s.update(ctx, name, value, false)
}

func (s *Solver) update(ctx context.Context, name, value string, add bool) error {
	name = dns.Fqdn(strings.ToLower(name))
	if err := s.check(); err != nil {
		return err
	}
	if !dns.IsSubDomain(s.Zone, name) {
		return fmt.Errorf("rfc2136: %s is not inside the zone %s", name, s.Zone)
	}
	ttl := s.TTL
	if ttl == 0 {
		ttl = 60
	}
	rr := &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}, Txt: txtStrings(value)}
	m := new(dns.Msg)
	m.SetUpdate(s.Zone)
	if add {
		m.Insert([]dns.RR{rr})
	} else {
		m.Remove([]dns.RR{rr})
	}
	alg := algorithms[s.Algorithm]
	m.SetTsig(s.KeyName, alg, 300, time.Now().Unix())

	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c := &dns.Client{Net: "tcp", Timeout: timeout, TsigSecret: map[string]string{s.KeyName: s.Secret}}
	in, _, err := c.ExchangeContext(ctx, m, s.Server)
	if err != nil {
		return fmt.Errorf("rfc2136: update of %s at %s: %w", name, s.Server, err)
	}
	if in.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("rfc2136: update of %s refused by %s: %s", name, s.Server, dns.RcodeToString[in.Rcode])
	}
	// The answer must be signed with the same key, or anyone on the path
	// could say "done" (RFC 8945 §5.3).
	if in.IsTsig() == nil {
		return fmt.Errorf("rfc2136: the answer of %s to the update of %s is not signed", s.Server, name)
	}
	return nil // a signature that does not verify came back as err above
}

// txtStrings cuts a value into the 255-byte character-strings of a TXT RDATA
// (RFC 1035 §3.3.14). An ACME value is 43 bytes: one string.
func txtStrings(v string) []string {
	var out []string
	for len(v) > 255 {
		out = append(out, v[:255])
		v = v[255:]
	}
	return append(out, v)
}
