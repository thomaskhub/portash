//go:build !unix

package tokens

import "os"

// ownerOK has nothing to check where files have no Unix owner.
func ownerOK(os.FileInfo) bool { return true }
