// SPDX-License-Identifier: BSD-3-Clause

package servercert

import "io/fs"

// checkPrivate accepts any directory on Windows: Go reports every directory
// there as 0777, because access is decided by ACLs the mode does not show.
// Refusing on the mode would refuse every cache directory there is.
func checkPrivate(string, fs.FileMode) error { return nil }
