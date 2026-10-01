// SPDX-License-Identifier: BSD-3-Clause

package servercert

import "io/fs"

// checkPrivate accepts any directory on Windows: Go reports every directory
// there as 0777, and neither access nor ownership is decided by anything
// fs.FileInfo shows -- ACLs decide both. Refusing on the mode would refuse
// every cache directory there is. Restrict the directory's ACL to the
// service account yourself; New still refuses a symbolic link and a
// directory this process cannot write.
func checkPrivate(string, fs.FileInfo, int) error { return nil }
