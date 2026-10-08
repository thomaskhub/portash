//go:build linux

// Package session runs a login shell behind a fresh pseudo-terminal so that
// everything the shell prints can be copied to a recorder.
package session

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	tiocgptn   = 0x80045430
	tiocsptlck = 0x40045431
	tiocgwinsz = 0x5413
	tiocswinsz = 0x5414
)

func ioctl(fd, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); e != 0 {
		return e
	}
	return nil
}

// IsTerminal reports whether f is a terminal.
func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	return ioctl(f.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&t))) == nil
}

func openPTY() (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(master.Fd(), tiocsptlck, uintptr(unsafe.Pointer(&unlock))); err != nil {
		master.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctl(master.Fd(), tiocgptn, uintptr(unsafe.Pointer(&n))); err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func makeRaw(fd uintptr) (restore func(), err error) {
	var old syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old))); err != nil {
		return nil, err
	}
	t := old
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN], t.Cc[syscall.VTIME] = 1, 0
	if err := ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&t))); err != nil {
		return nil, err
	}
	return func() { ioctl(fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old))) }, nil
}

func copySize(from, to uintptr) {
	var ws [4]uint16
	if ioctl(from, tiocgwinsz, uintptr(unsafe.Pointer(&ws))) == nil {
		ioctl(to, tiocswinsz, uintptr(unsafe.Pointer(&ws)))
	}
}

// RunPTY runs cmd on a new pseudo-terminal wired to our own terminal, copying
// its output to rec as well. prepare, if set, runs after the terminal exists
// and before the command starts, with the new terminal's path; the sandbox
// uses it so the shell can write to its own terminal but not to the outer
// one (which would bypass the recording). It returns the exit code.
func RunPTY(cmd *exec.Cmd, rec io.Writer, prepare func(tty string) error) (int, error) {
	master, slave, err := openPTY()
	if err != nil {
		return 1, err
	}
	defer master.Close()
	if prepare != nil {
		if err := prepare(slave.Name()); err != nil {
			slave.Close()
			return 1, err
		}
	}
	copySize(os.Stdin.Fd(), master.Fd())
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		return 1, err
	}
	slave.Close()

	restore, err := makeRaw(os.Stdin.Fd())
	if err == nil {
		defer restore()
	}
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	go func() {
		for range winch {
			copySize(os.Stdin.Fd(), master.Fd())
		}
	}()

	go io.Copy(master, os.Stdin)
	out := io.Writer(os.Stdout)
	if rec != nil {
		out = io.MultiWriter(os.Stdout, &bestEffort{w: rec})
	}
	io.Copy(out, master) // returns EIO when the shell exits
	return exitCode(cmd.Wait())
}

func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return 1, err
}

// bestEffort keeps the session alive if the recorder goes away; the gap is
// visible in the audit log because the recording ends early.
type bestEffort struct {
	w    io.Writer
	dead bool
}

func (b *bestEffort) Write(p []byte) (int, error) {
	if !b.dead {
		if _, err := b.w.Write(p); err != nil {
			b.dead = true
		}
	}
	return len(p), nil
}
