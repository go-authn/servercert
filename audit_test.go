// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

// The tests in this file were proofs of concept of a security audit; each
// failed before its fix and stays as its regression test.

package servercert

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A symbolic link ABOVE the cache directory, owned by a user who can
// re-point it, is refused: re-pointed after New, it sent the ACME account
// key into a 0777 directory elsewhere. The real path is the control.
func TestCacheDirParentSymlinkIsRefused(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	evil := filepath.Join(root, "evil")
	os.MkdirAll(filepath.Join(good, "acme"), 0o700)
	os.MkdirAll(filepath.Join(evil, "acme"), 0o700)
	os.Chmod(filepath.Join(evil, "acme"), 0o777)
	link := filepath.Join(root, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	src, err := New(acmeCache(filepath.Join(link, "acme")))
	if err == nil {
		os.Remove(link)
		os.Symlink(evil, link) // whoever owns the link re-points it
		src.mgr.Cache.Put(context.Background(), "acme_account+key", []byte("PRIVATE KEY"))
		_, leaked := os.Stat(filepath.Join(evil, "acme", "acme_account+key"))
		t.Fatalf("New accepted a cache under a symbolic link (key written to the 0777 directory: %v)", leaked == nil)
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("refused, but not for the link: %v", err)
	}
	if _, err := New(acmeCache(filepath.Join(good, "acme"))); err != nil {
		t.Errorf("control: the real path: %v", err)
	}
}

// A parent others may write to can have the cache renamed away and another
// put in its place; a sticky one (/tmp) cannot, and is accepted.
func TestCacheDirParentWritableByOthersIsRefused(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	os.Mkdir(parent, 0o700)
	os.Chmod(parent, 0o777)
	t.Cleanup(func() { os.Chmod(parent, 0o700) })
	_, err := New(acmeCache(filepath.Join(parent, "acme")))
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Errorf("a 0777 parent: %v, want a refusal", err)
	}
	os.Chmod(parent, 0o777|fs.ModeSticky)
	if _, err := New(acmeCache(filepath.Join(parent, "acme"))); err != nil {
		t.Errorf("a sticky 1777 parent: %v", err)
	}
}

// The ancestor rule itself: a parent of another user is refused; root's
// symbolic links (macOS's /var) are accepted, and only root's.
func TestCheckAncestor(t *testing.T) {
	dir := t.TempDir()
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	me := os.Geteuid()
	if err := checkAncestor(dir, fi, me); err != nil {
		t.Errorf("own directory: %v", err)
	}
	if me != 0 {
		if err := checkAncestor(dir, fi, me+1); err == nil || !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("another user's directory: %v, want a refusal", err)
		}
	}
	for _, c := range []struct {
		uid uint32
		ok  bool
	}{{0, true}, {uint32(me) + 1, false}} {
		err := checkAncestor("/l", linkInfo{c.uid}, me)
		if (err == nil) != c.ok {
			t.Errorf("a symbolic link of uid %d: %v, want accepted = %v", c.uid, err, c.ok)
		}
	}
}

// linkInfo is a symbolic link's fs.FileInfo, of uid.
type linkInfo struct{ uid uint32 }

func (linkInfo) Name() string       { return "l" }
func (linkInfo) Size() int64        { return 0 }
func (linkInfo) Mode() fs.FileMode  { return fs.ModeSymlink | 0o777 }
func (linkInfo) ModTime() time.Time { return time.Time{} }
func (linkInfo) IsDir() bool        { return false }
func (l linkInfo) Sys() any         { return &syscall.Stat_t{Uid: l.uid} }
