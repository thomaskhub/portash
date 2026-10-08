//go:build !linux

package authd

import "errors"

const DefaultSocket = "/run/portash/authd.sock"

var errUnsupported = errors.New("portash authd runs on Linux servers")

func VerifyTOTP(socket, code string) error   { return errUnsupported }
func Log(socket, event, detail string) error { return errUnsupported }
