//go:build !linux

package main

import (
	"context"
	"errors"
)

var errServerOnly = errors.New("this command runs on Linux servers")

func cmdAuthd(_ context.Context, args []string) error { return errServerOnly }
func cmdTOTP(args []string) error                     { return errServerOnly }
func cmdPAMTOTP(args []string) error                  { return errServerOnly }
func cmdShell(args []string) error                    { return errServerOnly }
