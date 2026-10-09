//go:build linux

// Package sandbox confines a session with Landlock, a Linux kernel feature
// (5.13+): after Restrict, the process and everything it starts can only
// create, change or delete files beneath the allowed paths. Reading is not
// restricted. The kernel enforces it on every system call, so how a command is
// spelled, scripted or obfuscated doesn't matter, and it applies to root too.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	sysCreateRuleset = 444
	sysAddRule       = 445
	sysRestrictSelf  = 446

	createRulesetVersion = 1
	rulePathBeneath      = 1
	prSetNoNewPrivs      = 38
	oPath                = 0x200000 // O_PATH, missing from package syscall

	accessExecute    = 1 << 0
	accessWriteFile  = 1 << 1
	accessReadFile   = 1 << 2
	accessReadDir    = 1 << 3
	accessRemoveDir  = 1 << 4
	accessRemoveFile = 1 << 5
	accessMakeChar   = 1 << 6
	accessMakeDir    = 1 << 7
	accessMakeReg    = 1 << 8
	accessMakeSock   = 1 << 9
	accessMakeFifo   = 1 << 10
	accessMakeBlock  = 1 << 11
	accessMakeSym    = 1 << 12
	accessRefer      = 1 << 13 // ABI 2: rename/link across directories
	accessTruncate   = 1 << 14 // ABI 3
)

// ABI returns the kernel's Landlock version, or 0 if unavailable.
func ABI() int {
	v, _, e := syscall.Syscall(sysCreateRuleset, 0, 0, createRulesetVersion)
	if e != 0 {
		return 0
	}
	return int(v)
}

func writeAccess(abi int) uint64 {
	a := uint64(accessWriteFile | accessRemoveDir | accessRemoveFile | accessMakeChar | accessMakeDir |
		accessMakeReg | accessMakeSock | accessMakeFifo | accessMakeBlock | accessMakeSym)
	if abi >= 2 {
		a |= accessRefer
	}
	if abi >= 3 {
		a |= accessTruncate
	}
	return a
}

// fileOnly are the write rights that apply to a file rather than a directory.
func fileOnly(abi int) uint64 {
	a := uint64(accessWriteFile)
	if abi >= 3 {
		a |= accessTruncate
	}
	return a
}

// DefaultWritable is what a shell needs to work at all: /dev/null and friends
// (writing existing device files only, never creating them) and the temp
// directories. The session adds its own terminal; other terminals, including
// the one sshd allocated, stay unwritable so output can't skip the recording.
var DefaultWritable = []string{"/tmp", "/var/tmp", "/dev/null", "/dev/tty", "/dev/zero", "/dev/full"}

// MinABI is the oldest Landlock version Restrict accepts by default. Before
// ABI 3 (Linux 6.2) truncate(2) is not covered, so a session could empty any
// file its user may write.
const MinABI = 3

// Restrict confines the calling process to writing only beneath writable.
// Paths that don't exist are skipped. It sets no_new_privs, so setuid
// programs such as sudo stop working inside the sandbox. Kernels older than
// minABI are refused.
func Restrict(writable []string, minABI int) error {
	abi := ABI()
	if abi < 1 {
		return errors.New("this kernel has no Landlock support (needs Linux 5.13+ with landlock in the LSM list)")
	}
	if abi < minABI {
		return fmt.Errorf("this kernel's Landlock (ABI %d) can't stop truncating files; needs ABI %d (Linux 6.2+)", abi, minABI)
	}
	handled := writeAccess(abi)
	attr := struct{ handledFS uint64 }{handled}
	fd, _, e := syscall.Syscall(sysCreateRuleset, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return fmt.Errorf("landlock_create_ruleset: %v", e)
	}
	ruleset := int(fd)
	defer syscall.Close(ruleset)

	for _, p := range writable {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		allowed := handled
		if !fi.IsDir() {
			allowed = fileOnly(abi)
		}
		if err := addRule(ruleset, p, allowed); err != nil {
			return fmt.Errorf("allow %s: %w", p, err)
		}
	}
	// Both calls below act on this OS thread only. Pin the calling goroutine
	// to it for good, so whatever it execs or forks later starts from the
	// restricted thread and not from another one the scheduler picked.
	runtime.LockOSThread()
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %v", e)
	}
	if _, _, e := syscall.Syscall(sysRestrictSelf, uintptr(ruleset), 0, 0); e != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", e)
	}
	return nil
}

// UserManager returns the socket of a service manager running as uid
// outside any sandbox (systemd --user, or a D-Bus session bus), or "". A
// sandboxed session could ask it to start a process (systemd-run --user)
// that the sandbox doesn't cover.
func UserManager(uid int) string {
	dir := fmt.Sprintf("/run/user/%d", uid)
	for _, p := range []string{dir + "/systemd/private", dir + "/bus"} {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

func addRule(ruleset int, path string, allowed uint64) error {
	fd, err := syscall.Open(path, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	// struct landlock_path_beneath_attr is packed: u64 allowed_access, s32 parent_fd.
	var buf [12]byte
	*(*uint64)(unsafe.Pointer(&buf[0])) = allowed
	*(*int32)(unsafe.Pointer(&buf[8])) = int32(fd)
	if _, _, e := syscall.Syscall6(sysAddRule, uintptr(ruleset), rulePathBeneath, uintptr(unsafe.Pointer(&buf[0])), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}
