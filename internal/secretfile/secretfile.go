// Package secretfile writes a secret to a file that must not exist yet.
package secretfile

import (
	"errors"
	"fmt"
	"os"
)

// ErrExists is returned when the file is already there.
var ErrExists = errors.New("file already exists")

// WriteNew creates path with mode 0600 and writes data to it. It never
// replaces a file: an existing file, or a symlink at path (O_EXCL does not
// follow it), is an error and nothing is written. The data is flushed to disk
// before it returns; on any error the file is removed again.
func WriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s: %w", path, ErrExists)
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}
