//go:build !linux

package sandbox

import "errors"

var DefaultWritable []string

const MinABI = 3

func ABI() int { return 0 }

func Restrict(writable []string, minABI int) error {
	return errors.New("the sandbox needs Linux (Landlock)")
}

func UserManager(uid int) string { return "" }
