// SPDX-License-Identifier: BSD-3-Clause

//go:build !unix && !windows

package servercert

import (
	"fmt"
	"io/fs"
)

// checkPrivate refuses a directory group or others can reach. The owner is
// not checked: this platform reports none the way Unix does.
func checkPrivate(dir string, fi fs.FileInfo, _ int) error {
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("servercert: cache directory %s is accessible by group or others (%v); it holds private keys: chmod 700 it", dir, fi.Mode().Perm())
	}
	return nil
}
