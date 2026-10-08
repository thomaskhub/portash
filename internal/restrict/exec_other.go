//go:build windows

package restrict

import "errors"

type Options struct {
	Name       string
	AllowPTY   bool
	VerifyTOTP func(code string) error
}

func Run(policyFile string, o Options) error {
	return errors.New("portash restrict runs on the SSH server (Linux/macOS)")
}
