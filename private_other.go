// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package servercert

import (
	"fmt"
	"io/fs"
)

// checkPrivate refuses a directory group or others can reach: the cache holds
// the ACME account key and every certificate's private key.
func checkPrivate(dir string, mode fs.FileMode) error {
	if mode.Perm()&0o077 != 0 {
		return fmt.Errorf("servercert: cache directory %s is accessible by group or others (%v); it holds private keys: chmod 700 it", dir, mode.Perm())
	}
	return nil
}
