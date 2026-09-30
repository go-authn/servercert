// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func acmeCache(dir string) Config {
	return Config{ACME: &ACME{Domains: []string{"a.example.org"}, CacheDir: dir}}
}

// A symbolic link as the cache directory is refused, even to a directory
// that would itself be accepted: the check must be of the directory named.
func TestCacheDirSymlinkRefused(t *testing.T) {
	target := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "acme")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot make a symbolic link here: %v", err)
	}
	_, err := New(acmeCache(link))
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("New with a symlinked cache = %v, want a refusal", err)
	}
	// Positive control: the directory it leads to is accepted, and so is
	// the link's name spelled with a trailing separator removed by Clean.
	if _, err := New(acmeCache(target + string(filepath.Separator))); err != nil {
		t.Fatalf("the target itself: %v", err)
	}
}

// A 0700 directory owned by another user (root's, when not running as root)
// is refused, directly and through a symbolic link.
func TestCacheDirOwnedByAnotherUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership is an ACL matter on Windows; not checked there")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: every root-owned directory is ours")
	}
	var other string
	for _, d := range []string{"/private/var/backups", "/root", "/var/root"} {
		if fi, err := os.Lstat(d); err == nil && fi.IsDir() && fi.Mode().Perm() == 0o700 {
			other = d
			break
		}
	}
	if other == "" {
		t.Skip("no 0700 directory owned by another user here")
	}
	if _, err := New(acmeCache(other)); err == nil || !strings.Contains(err.Error(), "belongs to uid") {
		t.Fatalf("New with %s (another user's, 0700) = %v, want a refusal", other, err)
	}
	link := filepath.Join(t.TempDir(), "acme")
	if err := os.Symlink(other, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(acmeCache(link)); err == nil {
		t.Fatalf("New with a symlink to %s accepted it", other)
	}
}

// The owner check itself, independent of what directories this machine has.
func TestCheckPrivateOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ownership is an ACL matter on Windows; not checked there")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(dir, fi, os.Geteuid()); err != nil {
		t.Fatalf("own directory refused: %v", err)
	}
	if err := checkPrivate(dir, fi, os.Geteuid()+1); err == nil || !strings.Contains(err.Error(), "belongs to uid") {
		t.Fatalf("directory of another uid: %v, want a refusal", err)
	}
}

// A 0500 directory this user owns passes the mode and owner checks and still
// cannot hold a certificate: New must say so.
func TestCacheDirNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a read-only directory cannot be made with mode bits on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes through a mode-0500 directory")
	}
	dir := filepath.Join(t.TempDir(), "cache")
	os.Mkdir(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if _, err := New(acmeCache(dir)); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("New with an unwritable cache = %v, want a refusal", err)
	}
	os.Chmod(dir, 0o700)
	if _, err := New(acmeCache(dir)); err != nil {
		t.Fatalf("the same directory made writable: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("the writability probe left %d entries behind", len(ents))
	}
}

// A JSON body longer than the bound is refused, not handed on truncated.
func TestOrderLocationsRefusesOversizedBody(t *testing.T) {
	for _, n := range []int{maxOrderBody, maxOrderBody + 1} {
		body := bytes.Repeat([]byte(" "), n) // valid JSON whitespace, not an order
		c := withOrderLocations(&http.Client{Transport: stubTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(bytes.NewReader(body))}, nil
		})})
		res, err := c.Post("https://ca.test/order", "application/jose+json", nil)
		if n > maxOrderBody {
			if err == nil || !strings.Contains(err.Error(), "refused rather than truncated") {
				t.Fatalf("%d bytes: err %v, want a refusal", n, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		got, _ := io.ReadAll(res.Body)
		if len(got) != n {
			t.Fatalf("%d bytes: handed on %d", n, len(got))
		}
	}
}
