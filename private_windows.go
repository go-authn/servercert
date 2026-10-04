// SPDX-License-Identifier: BSD-3-Clause

package servercert

import (
	"fmt"
	"io/fs"
)

// checkPrivate accepts any directory on Windows: Go reports every directory
// there as 0777, and neither access nor ownership is decided by anything
// fs.FileInfo shows -- ACLs decide both. Refusing on the mode would refuse
// every cache directory there is. Restrict the directory's ACL to the
// service account yourself; New still refuses a symbolic link and a
// directory this process cannot write.
func checkPrivate(string, fs.FileInfo, int) error { return nil }

// checkAncestor refuses a symbolic link above the cache: whoever owns it can
// re-point it. Who may change a directory is an ACL matter on Windows, which
// fs.FileInfo does not show.
func checkAncestor(path string, fi fs.FileInfo, _ int) error {
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link, which can be re-pointed; name the real path", path)
	}
	return nil
}
