//go:build unix

// Package fsown gives files written by root the owner of the folder they are
// in. The gateway runs as its own user and owns its state folder; an admin
// running `sudo portash token add` must leave files that user can read.
package fsown

import (
	"os"
	"path/filepath"
	"syscall"
)

// LikeParent chowns path to the owner of its parent folder when run as root.
// Elsewhere it does nothing: a non-root process can't give files away, and
// its files are already its own.
func LikeParent(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil
	}
	return os.Lchown(path, int(st.Uid), int(st.Gid))
}

// WriteFile writes data to path through a new temporary file and a rename,
// owned like the folder. Root writing into a folder another user owns must
// never open a name that user could have made a symlink.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := LikeParent(tmp.Name()); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
