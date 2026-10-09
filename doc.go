// SPDX-License-Identifier: BSD-3-Clause

// Package servercert says where a daemon's TLS server certificate comes
// from: a certificate and key on disk, re-read when they change, or an ACME
// CA through golang.org/x/crypto/acme/autocert, External Account Binding
// included.
//
//	src, err := servercert.New(servercert.Config{
//	    ACME: &servercert.ACME{
//	        DirectoryURL:   "https://acme-v02.harica.gr/acme/<uuid>/directory", // as cm.harica.gr shows it
//	        Domains:        []string{"files.example.org"},
//	        CacheDir:       "/var/lib/fileshare/acme",
//	        EABKeyID:       "<key ID from cm.harica.gr>",
//	        EABHMACKeyFile: "/etc/fileshare/harica-hmac",
//	    },
//	    OnError: func(err error) { log.Print(err) },
//	})
//	tc := src.TLSConfig()
//	tc.NextProtos = append(tc.NextProtos, "sunrpc") // APPEND: keep acme-tls/1
//
// # Files
//
// CertFile and KeyFile are read by [New], which fails at once on a pair that
// is unreadable, does not parse, or whose key is not the certificate's. At
// most once every 10 seconds, during a handshake, the files are read again;
// a pair whose contents changed is parsed (without holding any lock) and
// swapped in. A changed pair that does not load -- the certificate written
// before its key, a truncated file -- is reported once to Config.OnError and
// the last good pair stays in service.
//
// # ACME
//
// autocert answers two challenge types and no other:
//
//   - tls-alpn-01 (RFC 8737): the CA connects to port 443 of the domain and
//     negotiates the "acme-tls/1" ALPN protocol. [Source.TLSConfig] carries
//     that protocol; the caller must APPEND its own to NextProtos, never
//     replace them.
//   - http-01 (RFC 8555 §8.3): the CA fetches a token on port 80. With
//     ACME.HTTPChallenge, [Source.HTTPHandler] serves it and must be on :80.
//
// There is no dns-01, hence no wildcard, and no IP address certificates;
// [Config.Check] refuses both.
//
// A CA may need no challenge at all. autocert's order flow returns as soon
// as a new order is already "ready" (RFC 8555 §7.1.6): every authorization
// is valid before any challenge is attempted. That is the case of GÉANT TCS,
// served by HARICA since 2025-01-10 (it replaced Sectigo): an Enterprise
// ADMIN account (OV certificates) with pre-validated domains gets its
// certificates with no ACME challenge; an Enterprise User account (DV) is
// challenged like any other, and either way the domain's CAA must allow
// harica.gr (DFN: https://doku.tid.dfn.de/de:dfnpki:tcs:2025:acme). The
// directory URL, the EAB key ID and the HMAC key are all shown by
// https://cm.harica.gr for the ACME account -- of the form
// https://acme-v02.harica.gr/acme/<uuid>/directory in SURF's instructions
// (https://servicedesk.surf.nl/wiki/spaces/WIKI/pages/147098524/ACME, June
// 2025); older guides show another form, so copy it rather than build it. So
// an INTERNAL server reachable on neither port 80 nor 443 from the Internet
// can still get a publicly trusted certificate.
//
// Certificates are obtained at the first TLS handshake whose SNI names one of
// ACME.Domains, or before any client with [Source.Prefetch], then renewed by
// autocert before they expire. A client that connects by IP address sends no
// SNI and is served the FIRST domain's certificate, which it still checks
// against the address it dialled.
//
// External Account Binding (RFC 8555 §7.3.4) ties the ACME account to an
// account at the CA. The HMAC key is a secret, so the configuration names a
// FILE holding it (base64url, as CAs hand it out), never the key itself.
//
// One defect of x/crypto/acme is worked around here (golang/go#77704): after
// finalizing an order the CA is still processing, the client polls the
// Location header of the finalize response, which RFC 8555 does not put
// there; pebble and Buypass do not send it. The ACME client's transport
// supplies it from the order URL it saw earlier.
//
// # Tests
//
// The ACME tests obtain real certificates from pebble, Let's Encrypt's test
// CA, run in-process, and verify them with crypto/tls against pebble's root:
// tls-alpn-01, http-01, EAB required (absent, wrong and right keys), and a
// pre-validated domain issued with no challenge port open.
package servercert
