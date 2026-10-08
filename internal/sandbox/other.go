//go:build !linux

package sandbox

import "errors"

var DefaultWritable []string

func ABI() int { return 0 }

func Restrict(writable []string) error { return errors.New("the sandbox needs Linux (Landlock)") }
