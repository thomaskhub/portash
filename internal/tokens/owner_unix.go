//go:build unix

package tokens

import (
	"os"
	"syscall"
)

// ownerOK reports whether a file belongs to root or to the user this process
// runs as: nobody else may have put a token there.
func ownerOK(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	return st.Uid == 0 || int(st.Uid) == os.Getuid()
}
