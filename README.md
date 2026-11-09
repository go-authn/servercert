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

Without `ACME.DNS` there is no `dns-01`, hence **no wildcard**; an
IP-address certificate is never issued. `Check` refuses both rather than letting
them fail at the first handshake.

### dns-01: a server the CA cannot reach (since v0.7.0)

`ACME.DNS` proves control of the names with a TXT record at
`_acme-challenge.<name>` ([RFC 8555 §8.4](https://www.rfc-editor.org/rfc/rfc8555#section-8.4)):
the server needs **no inbound port** and may sit on a private LAN address
(`class.example-school.fr` resolving to `192.168.1.10`), and `Domains` may hold a
wildcard (`*.example-school.fr`, which does not cover the base name: list both).
Issuance goes through `x/crypto/acme` directly (autocert has no dns-01): one
order, one certificate for every name, an authorization proved per name, a
propagation wait, finalize; the certificate and key are kept 0600 in `CacheDir`
and renewed in the background at the lesser of 30 days and a third of the
lifetime before expiry, the old one serving meanwhile. A failed order is not
retried for a minute (a CA's failed-validation limit is hit by a loop).

```go
servercert.ACME{
    Domains:  []string{"*.example-school.fr", "example-school.fr"},
    CacheDir: "/var/lib/relay/certs",
    DNS: &servercert.DNS{
        CredentialsFile: "/etc/relay/dns-update.conf", // 0600, owned by the user
        Provider: func(b []byte) (servercert.DNSSolver, error) { return rfc2136.New(b) },
        Resolver: "192.0.2.53:53", // optional: wait until the TXT is visible there
    },
}
```

The provider is a two-method interface, so providers stay out of this module:

```go
type DNSSolver interface {
    Present(ctx context.Context, name, value string) error // add one TXT value at name
    CleanUp(ctx context.Context, name, value string) error // remove that value only
}
```

A wildcard and its base name share one record name with two values, so both
methods work on one value, never the whole RRset. The records are removed
whatever the outcome. **Credentials** are read from `CredentialsFile` under the
checks of `EABHMACKeyFile` (absolute, 0600, owned by the effective user) and
handed to `Provider`; never an argument, an environment variable or a URL.
`DNS` excludes `HTTPChallenge`. `Check` keeps refusing IP addresses, and a
wildcard is refused unless `DNS` is set.

The module [`rfc2136`](rfc2136/) (`github.com/go-authn/servercert/rfc2136`,
a separate module, so this one carries no DNS library) is the provider for a
name server that takes RFC 2136 dynamic updates signed with TSIG (RFC 8945):
`hmac-sha256/384/512`, and an unsigned or wrongly signed answer is an error.
Its credentials file:

```
server    = 192.0.2.53:53
zone      = example-school.fr
key       = acme-update
algorithm = hmac-sha256   # optional
secret    = <base64 TSIG secret>
```

Certificates are obtained at the first TLS handshake whose SNI names one of
`Domains` — or **before any client, by `Source.Prefetch`** (since v0.5.0), which
a server calls once its listeners are up, so the first client does not wait
for an issuance. They are renewed before they expire: autocert renews at the
lesser of 30 days and a third of the lifetime before expiry, which suits the
shorter certificates CAs are moving to (Let's Encrypt's 45-day and 6-day
profiles). **A client that connects by IP address sends no SNI** and is served
the first domain's certificate (before v0.5.0 its handshake failed).

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
by **HARICA** since 2025-01-10 (it replaced Sectigo): an **Enterprise Admin**
ACME account gets **OV** certificates for the organisation's validated domains
with **no ACME challenge at all**
([DFN documentation](https://doku.tid.dfn.de/de:dfnpki:tcs:2025:acme):
*„Keine ACME Challenge"*; [RENATER](https://services.renater.fr/tcs/acme)).
An **Enterprise User** account is not that: its **DV** certificates always go
through an http or dns challenge, so it needs a port the CA can reach.

Two conditions, both from RENATER's documentation: the domain's **CAA** record,
if it has one, must allow `harica.gr` (`IN CAA 0 issue "harica.gr"`), or the
request stays *Pending*; and the server must reach `acme-v02.harica.gr` and
`ocsp-tls.harica.gr` outbound.

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

`New` also refuses a cache directory that is a symbolic link, one accessible
by group or others, one owned by a user other than the process's effective
user (it holds private keys; mode and owner are not checked on Windows, where
ACLs decide both -- restrict the directory's ACL to the service account
yourself), and one it cannot write (a file is created and removed there); it
creates a missing one `0700`, and checks what is there **after** creating it.
Every directory above the cache must be one only root or the effective user
can change, as sshd's StrictModes requires of the path to `authorized_keys`:
owned by one of them, and not writable by group or others unless sticky
(`/tmp`). A symbolic link above the cache is refused unless root owns it
(macOS's `/var` and `/tmp`): whoever owns a link can re-point it, and the
private keys with it. On Windows, a symbolic link anywhere in the path is
refused. A security audit found that only the last component was checked
(`TestCacheDirParentSymlinkIsRefused`).

`New` (and every reload) also refuses a **secret file** that group or others can
read or write: the TLS `KeyFile` and the `EABHMACKeyFile`, as OpenSSH refuses a
private key, with `chmod 600 it`. The mode is read from the opened file, not
its name. A replacement key written readable is not taken: the current
certificate keeps serving and `OnError` is called. Not checked on Windows (ACLs).
**Upgrade:** `chmod 600` (or `0400`) both files before deploying.

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

dns-01 runs against the same in-process pebble with **no challenge port open**:
the DNS stub answers the TXT records a test solver published, so pebble's own
validator does the lookup. Covered: one name; a wildcard with its base name
(two values at one record name, and a name two labels below the wildcard
refused); the cache reused with a solver that refuses everything; the records
removed after success and after failure; the control with a **wrong TXT value**
(refused, nothing cached, `OnError` told, no second attempt within a minute);
a `Resolver` that never sees the right value stopping the order before the CA is
asked. `rfc2136` is tested against a TSIG-verifying UPDATE server (wrong key,
unsigned answer, zone check, delete of one value) and `FuzzParseCredentials`.
