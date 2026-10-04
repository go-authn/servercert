// SPDX-License-Identifier: BSD-3-Clause

//go:build unix

package servercert

import (
	"fmt"
	"io/fs"
	"syscall"
)

// checkPrivate refuses a directory group or others can reach, or one that
// belongs to a user other than euid: the cache holds the ACME account key
// and every certificate's private key, and a directory's owner can read and
// replace what is in it whatever its mode says.
func checkPrivate(dir string, fi fs.FileInfo, euid int) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("servercert: cache directory %s is accessible by group or others (%v); it holds private keys: chmod 700 it", dir, fi.Mode().Perm())
	}
	if owner := fi.Sys().(*syscall.Stat_t).Uid; int64(owner) != int64(euid) {
		return fmt.Errorf("servercert: cache directory %s belongs to uid %d, not to this process's uid %d; it holds private keys: chown it", dir, owner, euid)
	}
	return nil
}

// checkAncestor refuses a directory above the cache that someone other than
// root or euid could change, as sshd's StrictModes does for the path to
// authorized_keys: one that belongs to another user, or that its group or
// others may write to (a sticky one, like /tmp, is fine: there only an
// entry's owner may rename it). A symbolic link is accepted only when root
// owns it -- macOS's /var and /tmp are such links; whether it may be
// replaced is the question asked of its own parent, next. Any other link is
// refused: whoever owns it can re-point it, and the cache with it.
func checkAncestor(path string, fi fs.FileInfo, euid int) error {
	owner := fi.Sys().(*syscall.Stat_t).Uid
	switch {
	case fi.Mode()&fs.ModeSymlink != 0 && owner != 0:
		return fmt.Errorf("%s is a symbolic link of uid %d, who can re-point it; name the real path", path, owner)
	case owner != 0 && int64(owner) != int64(euid):
		return fmt.Errorf("%s belongs to uid %d, who can move the cache; it holds private keys", path, owner)
	case fi.Mode()&fs.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0:
		return fmt.Errorf("%s is writable by group or others (%v), who can move the cache; it holds private keys", path, fi.Mode().Perm())
	}
	return nil
}
