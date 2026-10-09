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

	defaultMaxLogBytes = 64 << 20 // rotate audit.log beyond this
	defaultKeepLogs    = 8        // rotated files kept: audit.log.1 ... .N
	defaultLogRate     = 10       // requests per second per user, all ops
	defaultLogBurst    = 100
	maxConnsPerUser    = 32

	defaultUserQuota = 2 << 30   // recordings kept per user before new ones are refused
	defaultReserve   = 512 << 20 // free space left for audit lines; recordings stop here
)

// logEvents are the events a session may write with the "log" op. authd
// writes its own (totp, record) itself.
var logEvents = map[string]bool{"session": true}

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

	// MaxLogBytes rotates audit.log when it grows beyond it (default 64 MiB);
	// KeepLogs rotated files are kept (default 8). LogRate and LogBurst limit
	// every request per user, so one account can't fill the disk or rotate
	// other people's lines away (and with a full disk make every login fail,
	// since sessions are refused when logging fails).
	MaxLogBytes int64
	KeepLogs    int
	LogRate     float64
	LogBurst    float64

	// UserQuota caps one user's recordings on disk (default 2 GiB): beyond
	// it, that user's new recordings (and so their terminal sessions) are
	// refused, nobody else's. Reserve is free space kept for audit lines
	// (default 512 MiB): recordings are refused or cut off below it.
	UserQuota int64
	Reserve   int64
	// freeBytes is overridable for tests.
	freeBytes func(dir string) int64

	mu        sync.Mutex
	recording map[int]int // open recordings per uid
	conns     map[int]int // open connections per uid
	buckets   map[int]*bucket
}

func statFree(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

func (s *Server) free() int64 {
	if s.freeBytes != nil {
		return s.freeBytes(s.LogDir)
	}
	return statFree(s.LogDir)
}

func (s *Server) reserve() int64 {
	if s.Reserve > 0 {
		return s.Reserve
	}
	return defaultReserve
}

// usage is the size of one user's recordings.
func usage(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

type bucket struct {
	tokens float64
	last   time.Time
}

// allow reports whether uid may make another request now.
func (s *Server) allow(uid int) bool {
	rate, burst := s.LogRate, s.LogBurst
	if rate <= 0 {
		rate = defaultLogRate
	}
	if burst <= 0 {
		burst = defaultLogBurst
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[int]*bucket{}
	}
	now := time.Now()
	b := s.buckets[uid]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		s.buckets[uid] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
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

func (s *Server) connect(uid int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = map[int]int{}
	}
	if s.conns[uid] >= maxConnsPerUser {
		return false
	}
	s.conns[uid]++
	return true
}

func (s *Server) disconnect(uid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[uid]--; s.conns[uid] <= 0 {
		delete(s.conns, uid)
	}
}

func (s *Server) handle(c *net.UnixConn) {
	defer c.Close()
	uid, pid, name, err := peer(c)
	if err != nil {
		return
	}
	if !s.connect(uid) {
		reply(c, errors.New("too many connections; slow down"))
		return
	}
	defer s.disconnect(uid)
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
	if !s.allow(uid) {
		reply(c, errors.New("too many requests; slow down"))
		return
	}
	switch req.Op {
	case "totp":
		err := s.TOTP.Check(name, req.Code)
		s.audit(name, uid, pid, "totp", result(err))
		reply(c, err)
	case "log":
		if !logEvents[req.Event] {
			reply(c, fmt.Errorf("unknown event %q", clean(req.Event, 32)))
			return
		}
		// Refuse if the line can't be written (disk full): the shell then
		// refuses the session rather than running it unlogged.
		reply(c, s.audit(name, uid, pid, req.Event, clean(req.Detail, 4096)))
	case "record":
		if !s.startRecording(uid) {
			reply(c, fmt.Errorf("too many open recordings for %s", name))
			return
		}
		defer s.endRecording(uid)
		if err := s.roomFor(name); err != nil {
			s.audit(name, uid, pid, "record", "refused: "+err.Error())
			reply(c, err)
			return
		}
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
// (SO_PEERCRED); event is one of ours, and detail is what that user's process
// sent, so it is quoted and can't add fields of its own.
func (s *Server) audit(name string, uid, pid int, event, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	line := fmt.Sprintf("%s user=%s uid=%d pid=%d event=%s detail=%s\n", time.Now().UTC().Format(time.RFC3339), name, uid, pid, event, strconv.Quote(detail))
	if s.Log != nil {
		s.Log.Print(strings.TrimSpace(line))
	}
	path := filepath.Join(s.LogDir, "audit.log")
	s.rotateLocked(path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rotateLocked moves audit.log to audit.log.1 (shifting older ones, dropping
// the oldest) once it is over MaxLogBytes. Errors are ignored: a failed
// rotation must not stop logging, and the write that follows reports a real
// problem.
func (s *Server) rotateLocked(path string) {
	limit, keep := s.MaxLogBytes, s.KeepLogs
	if limit <= 0 {
		limit = defaultMaxLogBytes
	}
	if keep <= 0 {
		keep = defaultKeepLogs
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Size() < limit {
		return
	}
	for i := keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", path, i), fmt.Sprintf("%s.%d", path, i+1))
	}
	os.Rename(path, path+".1")
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

// roomFor refuses a new recording when the disk is nearly full or the
// user is over their quota.
func (s *Server) roomFor(name string) error {
	if free := s.free(); free >= 0 && free < s.reserve() {
		return errors.New("log disk nearly full; recordings are paused")
	}
	quota := s.UserQuota
	if quota <= 0 {
		quota = defaultUserQuota
	}
	if usage(filepath.Join(s.LogDir, "sessions", name)) >= quota {
		return fmt.Errorf("recordings for %s are over their quota; ask an admin to archive them", name)
	}
	return nil
}

// copyCast writes an asciinema v2 file (replay with `asciinema play`).
func (s *Server) copyCast(f *os.File, r io.Reader) {
	start := time.Now()
	buf := make([]byte, 32<<10)
	var total, checked int64
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			full := false
			if total-checked >= 1<<20 { // look at the disk once a MiB
				checked = total
				free := s.free()
				full = free >= 0 && free < s.reserve()
			}
			if total > maxRecording || full {
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
