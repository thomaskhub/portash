//go:build linux

// Package authd is a small root daemon on a Unix socket. Login sessions run as
// the user, so they can't read TOTP secrets or write tamper-proof logs; they
// ask authd instead. authd identifies the caller by the kernel's peer
// credentials (SO_PEERCRED), never by anything the caller says.
package authd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"portash/internal/totp"
)

const (
	DefaultSocket = "/run/portash/authd.sock"
	maxRecording  = 256 << 20
	maxLine       = 16 << 10
)

type Request struct {
	Op     string `json:"op"`               // "totp", "log" or "record"
	Code   string `json:"code,omitempty"`   // totp
	Event  string `json:"event,omitempty"`  // log
	Detail string `json:"detail,omitempty"` // log, record
}

type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type Server struct {
	TOTP   totp.Store
	LogDir string // audit.log and sessions/ live here
	Log    *log.Logger

	mu        sync.Mutex
	recording map[int]int // open recordings per uid
}

// ListenAndServe serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// Anyone may connect; who they are comes from SO_PEERCRED.
	if err := os.Chmod(path, 0o666); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(s.LogDir, "sessions"), 0o700); err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(c.(*net.UnixConn))
	}
}

func peer(c *net.UnixConn) (uid, pid int, name string, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, 0, "", err
	}
	var cred *syscall.Ucred
	var serr error
	raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if serr != nil {
		return 0, 0, "", serr
	}
	u, err := user.LookupId(strconv.Itoa(int(cred.Uid)))
	if err != nil {
		return 0, 0, "", err
	}
	return int(cred.Uid), int(cred.Pid), u.Username, nil
}

func (s *Server) handle(c *net.UnixConn) {
	defer c.Close()
	uid, pid, name, err := peer(c)
	if err != nil {
		return
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Minute))
	br := bufio.NewReaderSize(io.LimitReader(c, maxLine), maxLine)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		reply(c, errors.New("bad request"))
		return
	}
	switch req.Op {
	case "totp":
		err := s.TOTP.Check(name, req.Code)
		s.audit(name, uid, pid, "totp", result(err))
		reply(c, err)
	case "log":
		// Refuse if the line can't be written (disk full): the shell then
		// refuses the session rather than running it unlogged.
		reply(c, s.audit(name, uid, pid, clean(req.Event, 32), clean(req.Detail, 4096)))
	case "record":
		if !s.startRecording(uid) {
			reply(c, fmt.Errorf("too many open recordings for %s", name))
			return
		}
		defer s.endRecording(uid)
		f, path, err := s.openRecording(name, pid, req.Detail)
		if err != nil {
			reply(c, err)
			return
		}
		defer f.Close()
		if err := s.audit(name, uid, pid, "record", path); err != nil {
			reply(c, err)
			return
		}
		reply(c, nil)
		c.SetReadDeadline(time.Time{})
		// Unbuffered from here: everything the session prints, timestamped.
		s.copyCast(f, io.MultiReader(br, c))
	default:
		reply(c, errors.New("unknown op"))
	}
}

func result(err error) string {
	if err != nil {
		return "fail: " + err.Error()
	}
	return "ok"
}

func reply(c net.Conn, err error) {
	r := Response{OK: err == nil}
	if err != nil {
		r.Error = err.Error()
	}
	b, _ := json.Marshal(r)
	c.Write(append(b, '\n'))
}

// clean keeps log lines single-line and bounded.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "..." // don't leave half a character
	}
	return s
}

// maxRecordings caps concurrent recordings per user, so one local user can't
// fill the disk with hundreds of 256 MiB casts at once.
const maxRecordings = 8

func (s *Server) startRecording(uid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recording == nil {
		s.recording = map[int]int{}
	}
	if s.recording[uid] >= maxRecordings {
		return false
	}
	s.recording[uid]++
	return true
}

func (s *Server) endRecording(uid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recording[uid]--; s.recording[uid] <= 0 {
		delete(s.recording, uid)
	}
}

// audit appends one line. user, uid and pid come from the kernel
// (SO_PEERCRED); event and detail are what that user's process sent.
func (s *Server) audit(name string, uid, pid int, event, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("%s user=%s uid=%d pid=%d event=%s %s\n", time.Now().UTC().Format(time.RFC3339), name, uid, pid, event, detail)
	if s.Log != nil {
		s.Log.Print(strings.TrimSpace(line))
	}
	f, err := os.OpenFile(filepath.Join(s.LogDir, "audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (s *Server) openRecording(name string, pid int, detail string) (*os.File, string, error) {
	dir := filepath.Join(s.LogDir, "sessions", name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%d.cast", time.Now().UTC().Format("20060102T150405Z"), pid))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", err
	}
	hdr, _ := json.Marshal(map[string]any{"version": 2, "width": 80, "height": 24,
		"timestamp": time.Now().Unix(), "title": clean(detail, 256)})
	f.Write(append(hdr, '\n'))
	return f, path, nil
}

// copyCast writes an asciinema v2 file (replay with `asciinema play`).
func (s *Server) copyCast(f *os.File, r io.Reader) {
	start := time.Now()
	buf := make([]byte, 32<<10)
	var total int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxRecording {
				f.WriteString(`[0,"o","\r\n[portash: recording size limit reached]\r\n"]` + "\n")
				io.Copy(io.Discard, r)
				return
			}
			ev, _ := json.Marshal([]any{time.Since(start).Seconds(), "o", string(buf[:n])})
			f.Write(append(ev, '\n'))
		}
		if err != nil {
			return
		}
	}
}

// ---- client side ----

func call(socket string, req Request) (net.Conn, error) {
	c, err := net.DialTimeout("unix", socket, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("portash authd not reachable: %w", err)
	}
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, 4096)).ReadBytes('\n')
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetReadDeadline(time.Time{})
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		c.Close()
		return nil, err
	}
	if !resp.OK {
		c.Close()
		return nil, errors.New(resp.Error)
	}
	return c, nil
}

// VerifyTOTP asks authd to check a code for the calling user.
func VerifyTOTP(socket, code string) error {
	c, err := call(socket, Request{Op: "totp", Code: code})
	if err != nil {
		return err
	}
	return c.Close()
}

// Log writes an audit line for the calling user.
func Log(socket, event, detail string) error {
	c, err := call(socket, Request{Op: "log", Event: event, Detail: detail})
	if err != nil {
		return err
	}
	return c.Close()
}

// Record opens a session recording; write the session's output to it.
func Record(socket, title string) (io.WriteCloser, error) {
	return call(socket, Request{Op: "record", Detail: title})
}
