//go:build unix

package totp

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive lock that other processes (authd and the PAM
// helper) respect too.
func lockFile(f *os.File) (func(), error) {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }, nil
}
