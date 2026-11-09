// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSSolver publishes and removes the TXT record of a dns-01 challenge
// (RFC 8555 §8.4). It is the whole of what a DNS provider has to do, so that
// providers live outside this module: the rfc2136 module next to it speaks
// RFC 2136 DNS UPDATE signed with TSIG (RFC 8945), and an adapter to any
// libdns provider (AppendRecords / DeleteRecords) is a few lines.
//
// name is the fully qualified record name with its trailing dot,
// "_acme-challenge.<domain>."; value is the TXT string, already the base64url
// SHA-256 digest of the key authorization. A wildcard and its base domain are
// two authorizations with the SAME name and two different values: Present adds
// a value next to the ones there and CleanUp removes that one value only.
// Present must be idempotent (a value already there is success), and CleanUp
// of a value that is not there is success too. Both honour ctx.
type DNSSolver interface {
	Present(ctx context.Context, name, value string) error
	CleanUp(ctx context.Context, name, value string) error
}

// DNS selects dns-01 (RFC 8555 §8.4) as the way to prove control of the names:
// the CA looks for a TXT record, so the server needs no inbound port and may
// sit on a private address. It is the only way to get a wildcard.
//
// Exactly one of Solver, or Provider with CredentialsFile, is given.
type DNS struct {
	// Solver is a ready provider, for one that needs no secret.
	Solver DNSSolver

	// CredentialsFile and Provider: the file holds the provider's secret (a
	// TSIG key, an API token); New reads it, under the same checks as
	// EABHMACKeyFile -- absolute, a regular file, not readable by group or
	// others, owned by the effective user on Unix -- and hands its bytes to
	// Provider. A secret is never a value in the configuration, nor on a
	// command line, in the environment or in a URL.
	CredentialsFile string
	Provider        func(credentials []byte) (DNSSolver, error)

	// Resolver, "host:port", is a DNS server asked (over TCP) for the TXT
	// record after Present, until it answers with every value: the record
	// is known to be visible before the CA is told to look. Empty: no check,
	// only PropagationWait.
	Resolver string

	// PropagationWait is slept after the records are published and visible to
	// Resolver (or just published, with none). Zero means 10 seconds; a
	// negative value means none. Secondary servers and caches take time; a CA
	// that looks too early marks the authorization invalid and the order is
	// lost.
	PropagationWait time.Duration

	// Timeout bounds one whole issuance: order, records, wait, validation,
	// finalization. Zero means 5 minutes.
	Timeout time.Duration
}

func (d *DNS) check() error {
	switch {
	case d.Solver != nil && (d.Provider != nil || d.CredentialsFile != ""):
		return errors.New("servercert: ACME.DNS: Solver and Provider/CredentialsFile are exclusive")
	case d.Solver == nil && (d.Provider == nil || d.CredentialsFile == ""):
		return errors.New("servercert: ACME.DNS needs a Solver, or a Provider and a CredentialsFile")
	}
	if d.CredentialsFile != "" {
		if err := absolute("ACME.DNS.CredentialsFile", d.CredentialsFile); err != nil {
			return err
		}
	}
	if d.Resolver != "" {
		if _, port, err := net.SplitHostPort(d.Resolver); err != nil || port == "" {
			return fmt.Errorf("servercert: ACME.DNS.Resolver %q is not host:port", d.Resolver)
		}
	}
	if d.Timeout < 0 {
		return errors.New("servercert: ACME.DNS.Timeout is negative")
	}
	return nil
}

// solver returns the provider, building it from the credentials file.
func (d *DNS) solver() (DNSSolver, error) {
	if d.Solver != nil {
		return d.Solver, nil
	}
	raw, err := readSecretFile(d.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("servercert: DNS credentials: %w", err)
	}
	s, err := d.Provider(raw)
	if err != nil {
		// Not quoting raw: it is a secret.
		return nil, fmt.Errorf("servercert: DNS credentials %s: %w", d.CredentialsFile, err)
	}
	if s == nil {
		return nil, fmt.Errorf("servercert: DNS credentials %s: Provider returned no solver", d.CredentialsFile)
	}
	return s, nil
}

// wildcardBase says whether d is "*.<base>" and gives base.
func wildcardBase(d string) (string, bool) { return strings.CutPrefix(d, "*.") }
