# servercert

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/servercert.svg)](https://pkg.go.dev/github.com/go-authn/servercert)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/servercert/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/servercert/actions/workflows/ci.yml)

**Where a daemon's TLS server certificate comes from**: a certificate and key
on disk, re-read when they change, or an ACME CA through
[`autocert`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert), External
Account Binding included. Pure Go, `CGO_ENABLED=0`.

```go
src, err := servercert.New(servercert.Config{
    CertFile: "/etc/fileshare/tls/fullchain.pem",
    KeyFile:  "/etc/fileshare/tls/privkey.pem",
    OnError:  func(err error) { log.Print(err) },
})
srv := &http.Server{Addr: ":443", Handler: h, TLSConfig: src.TLSConfig()}
srv.ListenAndServeTLS("", "")
```

## Files

`New` reads the pair and fails **now** on a pair that is unreadable, does not
parse, or whose key is not the certificate's. After that, at most once every
10 seconds and during a handshake, the files are read again; a changed pair is
parsed — without holding a lock — and swapped in.

A changed pair that does **not** load (the certificate written before its key,
a truncated file) is reported once to `OnError`, and **the last good pair stays
in service**. A renewal job that writes the two files one after the other never
takes the server down.

## ACME

autocert answers two challenge types, and no other:

| challenge | spec | the CA connects to |
|---|---|---|
| `tls-alpn-01` | [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737) | port **443**, ALPN `acme-tls/1` |
| `http-01` | [RFC 8555 §8.3](https://www.rfc-editor.org/rfc/rfc8555#section-8.3) | port **80**; set `HTTPChallenge` and serve `HTTPHandler` there |

No `dns-01`, hence **no wildcard** and no IP-address certificate: `Check`
refuses both rather than letting them fail at the first handshake.

Certificates are obtained **on demand**, at the first TLS handshake whose SNI
names one of `Domains`, and renewed before they expire. **A client that
connects by IP address sends no SNI and gets no certificate.**

`TLSConfig().NextProtos` holds `acme-tls/1`. **Append** your protocols, never
replace the slice: without it the CA's tls-alpn-01 validation fails. Append
them you must, too — a Go TLS server that advertises ALPN protocols refuses a
client whose offer shares none, so an NFS-over-TLS server adds `sunrpc`
([RFC 9289](https://www.rfc-editor.org/rfc/rfc9289)). `net/http` adds
`http/1.1` and `h2` by itself.

### An internal server, no port open: GÉANT TCS via HARICA

autocert returns at once when a new order is already `ready` — every
authorization valid before any challenge. That is what a CA with
**pre-validated domains** answers, and it is the case of **GÉANT TCS**, served
by **HARICA** since 2025-01-10 (it replaced Sectigo): an Enterprise account
with pre-validated domains gets certificates with **no ACME challenge at all**
([DFN documentation](https://doku.tid.dfn.de/de:dfnpki:tcs:2025:acme):
*„Keine ACME Challenge"*).

So a server that the Internet reaches on **neither port 80 nor 443** — a file
server inside a lab network — still gets a publicly trusted certificate:

```go
src, err := servercert.New(servercert.Config{
    ACME: &servercert.ACME{
        DirectoryURL:   "https://acme-v02.harica.gr/acme/<uuid>/directory", // the Server URL cm.harica.gr shows
        Email:          "it@example.org",
        Domains:        []string{"files.lab.example.org"},
        CacheDir:       "/var/lib/fileshare/acme",
        EABKeyID:       "<key ID from https://cm.harica.gr>",
        EABHMACKeyFile: "/etc/fileshare/harica-hmac", // base64url, as HARICA gives it
    },
    OnError: func(err error) { log.Print(err) },
})
```

The HMAC key is a secret: the configuration names a **file** holding it, never
the key itself.

### Let's Encrypt

```go
servercert.Config{ACME: &servercert.ACME{
    Domains:  []string{"files.example.org"}, // DirectoryURL empty: Let's Encrypt production
    CacheDir: "/var/lib/fileshare/acme",
}}
```

## What `Check` refuses

`Config.Check` touches nothing — no file read, no directory created — and
refuses: neither or both sources; half a file pair; ACME without domains or
cache directory; a relative path; half an EAB; a domain that is an IP address,
a wildcard, a single label, ends with a dot, or is not a valid host name; a
directory URL that is not https ([RFC 8555 §6.1](https://www.rfc-editor.org/rfc/rfc8555#section-6.1)).

`New` also refuses a cache directory accessible by group or others (it holds
private keys; not checked on Windows, where mode bits do not describe access)
and creates a missing one `0700`.

## A defect worked around

x/crypto/acme v0.57.0 ([golang/go#77704](https://github.com/golang/go/issues/77704)):
after finalizing an order the CA is still processing, the client polls the
`Location` header of the **finalize** response, which RFC 8555 does not put
there. Pebble and Buypass send none, and the certificate is never fetched. The
ACME client's transport supplies the header from the order URL it saw earlier;
a CA that sends it sees no difference. A test runs the same issuance without
the workaround and requires it to fail, so its removal is signalled the day
x/crypto is fixed.

## Tests

The ACME tests obtain real certificates from
[pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's test CA,
**run in-process** from its `ca`, `db`, `va` and `wfe` packages, with a TCP DNS
stub sending the test name to 127.0.0.1. Certificates are verified by
`crypto/tls` against pebble's root. Covered: tls-alpn-01; http-01 through
`HTTPHandler` (and its control with `HTTPChallenge` off); EAB required and
absent, wrong, unknown, then right in the same test; a pre-validated domain
issued with no challenge port open (and its control: no prior authorization,
no certificate).
