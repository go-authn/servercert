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
