// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type stubTransport func(*http.Request) (*http.Response, error)

func (f stubTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

func TestOrderLocations(t *testing.T) {
	const (
		orderURL    = "https://ca.test/order/1"
		finalizeURL = "https://ca.test/finalize/1"
		processing  = `{"status":"processing","finalize":"` + finalizeURL + `"}`
	)
	respond := map[string]*http.Response{}
	boom := errors.New("boom")
	c := withOrderLocations(&http.Client{Transport: stubTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/fail" {
			return nil, boom
		}
		return respond[r.Method+" "+r.URL.String()], nil
	})})
	res := func(code int, loc, ctype string, body io.ReadCloser) *http.Response {
		h := http.Header{}
		if loc != "" {
			h.Set("Location", loc)
		}
		if ctype != "" {
			h.Set("Content-Type", ctype)
		}
		return &http.Response{StatusCode: code, Header: h, Body: body}
	}
	text := func(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
	post := func(url string) *http.Response {
		t.Helper()
		r, err := c.Post(url, "application/jose+json", nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	finalize := func() string {
		t.Helper()
		respond["POST "+finalizeURL] = res(200, "", "application/json", text(processing))
		return post(finalizeURL).Header.Get("Location")
	}

	// A finalize response before any order was seen: untouched.
	if got := finalize(); got != "" {
		t.Fatalf("Location %q invented from nothing", got)
	}

	newOrder := `{"status":"pending","finalize":"` + finalizeURL + `"}`
	respond["POST https://ca.test/new-order"] = res(201, orderURL, "application/json", text(newOrder))
	r := post("https://ca.test/new-order")
	if b, _ := io.ReadAll(r.Body); string(b) != newOrder {
		t.Fatalf("the newOrder body reached the client as %q", b)
	}
	if got := finalize(); got != orderURL {
		t.Fatalf("finalize Location = %q, want %q", got, orderURL)
	}

	// An order fetched from its own URL (POST-as-GET) teaches it too.
	respond["POST https://ca.test/order/9"] = res(200, "", "application/json", text(newOrder))
	post("https://ca.test/order/9")
	if got := finalize(); got != "https://ca.test/order/9" {
		t.Fatalf("after a fetched order: Location %q", got)
	}

	// A CA that sends Location itself is never overridden.
	respond["POST "+finalizeURL] = res(200, "https://ca.test/order/own", "application/json", text(processing))
	if got := post(finalizeURL).Header.Get("Location"); got != "https://ca.test/order/own" {
		t.Fatalf("the CA's own Location became %q", got)
	}

	// Left alone: not JSON, not an order, not 2xx, not POST.
	for _, rr := range []*http.Response{
		res(200, "", "application/pem-certificate-chain", text("-----BEGIN")),
		res(201, "https://ca.test/acct/1", "application/json", text(`{"status":"valid"}`)),
		res(200, "", "application/json", text(`not json`)),
		res(400, "", "application/problem+json", text(`{"type":"badNonce"}`)),
	} {
		respond["POST https://ca.test/other"] = rr
		post("https://ca.test/other")
	}
	respond["GET https://ca.test/directory"] = res(200, "", "application/json", text(`{}`))
	if r, err := c.Get("https://ca.test/directory"); err != nil || r.StatusCode != 200 {
		t.Fatalf("GET: %v", err)
	}
	if got := finalize(); got != "https://ca.test/order/own" {
		t.Fatalf("an unrelated response changed the mapping: %q", got)
	}

	// Errors pass through: the transport's, and a body that breaks.
	if _, err := c.Post("https://ca.test/fail", "", nil); !errors.Is(err, boom) {
		t.Fatalf("transport error became %v", err)
	}
	respond["POST https://ca.test/broken"] = res(201, orderURL, "application/json", failingBody{})
	if _, err := c.Post("https://ca.test/broken", "", nil); err == nil {
		t.Fatal("a body that failed to read was passed on as fine")
	}

	// nil means http.DefaultClient, with its default transport, unchanged.
	d := withOrderLocations(nil)
	if d == http.DefaultClient || http.DefaultClient.Transport != nil {
		t.Fatal("http.DefaultClient itself was modified")
	}
	if ol, ok := d.Transport.(*orderLocations); !ok || ol.next != http.DefaultTransport {
		t.Fatalf("nil client: transport %T", d.Transport)
	}
}
