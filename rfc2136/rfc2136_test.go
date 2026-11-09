package rfc2136

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

var secret = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// zoneServer is a primary that takes TSIG-signed UPDATEs for one zone, as
// BIND would: it verifies the signature, refuses names outside the zone, adds
// and deletes single RRs, and signs its answer.
type zoneServer struct {
	mu       sync.Mutex
	txt      map[string][]string
	updates  int
	addr     string
	unsigned bool // answer without a signature
}

func startZone(t *testing.T, zone, key string) *zoneServer {
	t.Helper()
	z := &zoneServer{txt: map[string][]string{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept }, TsigSecret: map[string]string{key: secret}, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch {
		case r.Opcode != dns.OpcodeUpdate:
			m.Rcode = dns.RcodeNotImplemented
		case r.IsTsig() == nil || w.TsigStatus() != nil:
			m.Rcode = dns.RcodeNotAuth // RFC 8945 §5.3: unsigned or badly signed
		case len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, zone):
			m.Rcode = dns.RcodeNotAuth
		default:
			z.mu.Lock()
			z.updates++
			for _, rr := range r.Ns {
				if !dns.IsSubDomain(zone, rr.Header().Name) {
					m.Rcode = dns.RcodeNotZone
					break
				}
				txt, ok := rr.(*dns.TXT)
				if !ok {
					m.Rcode = dns.RcodeFormatError
					break
				}
				k, v := strings.ToLower(txt.Hdr.Name), strings.Join(txt.Txt, "")
				if txt.Hdr.Class == dns.ClassINET { // add
					z.txt[k] = append(z.txt[k], v)
				} else { // class NONE: delete this RR
					var keep []string
					for _, e := range z.txt[k] {
						if e != v {
							keep = append(keep, e)
						}
					}
					z.txt[k] = keep
				}
			}
			z.mu.Unlock()
		}
		if t := r.IsTsig(); t != nil && !z.unsigned {
			m.SetTsig(key, dns.HmacSHA256, 300, int64(t.TimeSigned))
		}
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	z.addr = ln.Addr().String()
	return z
}

func (z *zoneServer) values(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return append([]string(nil), z.txt[name]...)
}

func solver(z *zoneServer) *Solver {
	return &Solver{Server: z.addr, Zone: "class.example.fr.", KeyName: "acme.", Algorithm: "hmac-sha256", Secret: secret}
}

func TestPresentAndCleanUp(t *testing.T) {
	z := startZone(t, "class.example.fr.", "acme.")
	s := solver(z)
	ctx := context.Background()
	const name = "_acme-challenge.class.example.fr."

	if err := s.Present(ctx, name, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Present(ctx, strings.ToUpper(name), "v2"); err != nil { // a wildcard and its base: one name
		t.Fatal(err)
	}
	if got := z.values(name); len(got) != 2 {
		t.Fatalf("values %v", got)
	}
	if err := s.CleanUp(ctx, name, "v1"); err != nil {
		t.Fatal(err)
	}
	if got := z.values(name); len(got) != 1 || got[0] != "v2" {
		t.Fatalf("after cleaning v1: %v", got)
	}
	if err := s.CleanUp(ctx, name, "never-there"); err != nil {
		t.Errorf("deleting an absent record: %v", err)
	}
}

func TestWrongKeyIsRefused(t *testing.T) {
	z := startZone(t, "class.example.fr.", "acme.")
	s := solver(z)
	s.Secret = base64.StdEncoding.EncodeToString([]byte("a different key, not the server's"))
	err := s.Present(context.Background(), "_acme-challenge.class.example.fr.", "v")
	if err == nil {
		t.Fatal("an update signed with the wrong key was accepted")
	}
	if len(z.values("_acme-challenge.class.example.fr.")) != 0 {
		t.Error("the record was added")
	}
	if strings.Contains(err.Error(), s.Secret) {
		t.Errorf("the error quotes the secret: %v", err)
	}
}

func TestUnsignedAnswerIsRefused(t *testing.T) {
	z := startZone(t, "class.example.fr.", "acme.")
	z.unsigned = true
	if err := solver(z).Present(context.Background(), "_acme-challenge.class.example.fr.", "v"); err == nil {
		t.Fatal("an unsigned answer was taken as success")
	}
}

func TestOutsideTheZoneIsRefusedBeforeSending(t *testing.T) {
	z := startZone(t, "class.example.fr.", "acme.")
	err := solver(z).Present(context.Background(), "_acme-challenge.other.example.fr.", "v")
	if err == nil || !strings.Contains(err.Error(), "not inside the zone") {
		t.Fatalf("err %v", err)
	}
	if z.updates != 0 {
		t.Error("an update was sent")
	}
}

func TestParseCredentials(t *testing.T) {
	good := "# relay\nserver = 192.0.2.53:53\nzone = Class.Example.FR\nkey = acme\nsecret = " + secret + "\n"
	s, err := ParseCredentials([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if s.Zone != "class.example.fr." || s.KeyName != "acme." || s.Algorithm != "hmac-sha256" || s.Server != "192.0.2.53:53" {
		t.Errorf("%+v", s)
	}
	for name, in := range map[string]string{
		"empty":          "",
		"no secret":      "server=a:53\nzone=z.fr\nkey=k\n",
		"unknown key":    good + "secrte = x\n",
		"duplicate":      good + "zone = other.fr\n",
		"no equals":      "server a:53\n",
		"md5":            good + "algorithm = hmac-md5\n",
		"sha1":           good + "algorithm = hmac-sha1\n",
		"secret not b64": strings.Replace(good, secret, "!!!", 1),
		"server no port": strings.Replace(good, "192.0.2.53:53", "192.0.2.53", 1),
		"too big":        good + strings.Repeat("#", maxCredentials),
	} {
		if _, err := ParseCredentials([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error quotes the secret", name)
		}
	}
}

func FuzzParseCredentials(f *testing.F) {
	f.Add("server = 192.0.2.53:53\nzone = class.example.fr\nkey = acme\nsecret = " + secret + "\n")
	f.Add("# c\nserver=a:1\nzone=z\nkey=k\nalgorithm=hmac-sha512\nsecret=AAAA")
	f.Add("=\n=\n")
	f.Add("secret = \x00\nzone = " + strings.Repeat("a.", 200))
	f.Fuzz(func(t *testing.T, in string) {
		s, err := ParseCredentials([]byte(in))
		if err != nil {
			// A short secret ("1") appears in any message ("rfc2136").
			if s != nil && len(s.Secret) >= 16 && strings.Contains(err.Error(), s.Secret) {
				t.Fatal("the error quotes the secret")
			}
			return
		}
		if err := s.check(); err != nil {
			t.Fatalf("accepted credentials that do not check: %v", err)
		}
		if !strings.HasSuffix(s.Zone, ".") || !strings.HasSuffix(s.KeyName, ".") {
			t.Fatalf("names not fully qualified: %+v", s)
		}
	})
}
