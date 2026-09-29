// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// orderLocations works around a defect of x/crypto/acme (v0.57.0,
// golang/go#77704).
//
// After finalizing an order the CA is still processing, CreateOrderCert
// polls the URL in the FINALIZE response's Location header. RFC 8555 §7.4
// puts no Location there, and pebble and Buypass send none -- so the poll
// goes to "" (`Post "": unsupported protocol scheme ""`) and the certificate
// is never fetched. Let's Encrypt sends one, which is why this goes
// unnoticed; whether HARICA does is not known here.
//
// The order's URL is known before that: it is the Location of the newOrder
// response (§7.4 requires it there), or the URL an order was fetched from.
// This transport remembers it by the order's finalize URL and supplies it on
// a finalize response that lacks it. A CA that sends the header sees no
// difference. The same workaround is in go-authn/bridge's tls.go.
type orderLocations struct {
	next http.RoundTripper

	mu         sync.Mutex
	byFinalize map[string]string // finalize URL -> order URL
}

// maxOrderBody bounds what is read of an order object.
const maxOrderBody = 1 << 20

func (o *orderLocations) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := o.next.RoundTrip(req)
	if err != nil || req.Method != http.MethodPost || res.StatusCode/100 != 2 ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		return res, err
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxOrderBody))
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	var order struct{ Finalize string }
	if json.Unmarshal(body, &order) != nil || order.Finalize == "" {
		return res, nil // not an order
	}
	here := req.URL.String()
	o.mu.Lock()
	defer o.mu.Unlock()
	switch loc := res.Header.Get("Location"); {
	case loc != "":
		o.byFinalize[order.Finalize] = loc // newOrder, or a CA that sends it
	case here == order.Finalize:
		if u, ok := o.byFinalize[here]; ok {
			res.Header.Set("Location", u) // the finalize response
		}
	default:
		o.byFinalize[order.Finalize] = here // an order fetched from its URL
	}
	return res, nil
}

// withOrderLocations returns a copy of c (nil: http.DefaultClient) whose
// transport is wrapped in orderLocations.
func withOrderLocations(c *http.Client) *http.Client {
	if c == nil {
		c = http.DefaultClient
	}
	cp := *c
	next := cp.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	cp.Transport = &orderLocations{next: next, byFinalize: map[string]string{}}
	return &cp
}
