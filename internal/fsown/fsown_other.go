//go:build !unix

package fsown

import "os"

// LikeParent does nothing outside Unix.
func LikeParent(path string) error { return nil }

// WriteFile is os.WriteFile outside Unix.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}
