//go:build linux

package authd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func start(t *testing.T, s *Server) (socket, logDir string) {
	t.Helper()
	dir := t.TempDir()
	socket, logDir = filepath.Join(dir, "run", "authd.sock"), filepath.Join(dir, "log")
	s.LogDir = logDir
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.ListenAndServe(ctx, socket); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	for range 100 {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("authd did not start")
	return
}

func readAudit(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLogDetailCannotForgeFields(t *testing.T) {
	socket, dir := start(t, &Server{})
	if err := Log(socket, "session", `x user=root uid=0 event=totp ok`); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(readAudit(t, dir))
	i := strings.Index(line, " detail=")
	if i < 0 {
		t.Fatalf("no detail field: %q", line)
	}
	head := line[:i]
	if strings.Count(head, "user=") != 1 || strings.Contains(head, "user=root") {
		t.Fatalf("fields before detail were changed: %q", head)
	}
	if !strings.HasSuffix(line, `detail="x user=root uid=0 event=totp ok"`) {
		t.Fatalf("detail is not one quoted value: %q", line)
	}
}

func TestLogRejectsUnknownEvent(t *testing.T) {
	socket, dir := start(t, &Server{})
	if err := Log(socket, "totp", "ok"); err == nil {
		t.Fatal("a session wrote an event reserved for authd")
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log")); err == nil {
		t.Fatal("a rejected event was logged")
	}
}

func TestLogIsRateLimited(t *testing.T) {
	socket, _ := start(t, &Server{LogRate: 1, LogBurst: 5})
	ok, refused := 0, 0
	for range 20 {
		if err := Log(socket, "session", "x"); err != nil {
			refused++
		} else {
			ok++
		}
	}
	if ok < 5 || ok > 8 || refused == 0 {
		t.Fatalf("ok=%d refused=%d, want about the burst of 5 accepted and the rest refused", ok, refused)
	}
}

func TestAuditRotates(t *testing.T) {
	socket, dir := start(t, &Server{MaxLogBytes: 500, KeepLogs: 3, LogRate: 1000, LogBurst: 1000})
	for range 60 {
		if err := Log(socket, "session", strings.Repeat("a", 100)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"audit.log", "audit.log.1", "audit.log.2", "audit.log.3"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.4")); err == nil {
		t.Fatal("more rotated files than KeepLogs allows")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "audit.log")); fi.Size() > 1000 {
		t.Fatalf("audit.log is %d bytes, rotation did not keep it small", fi.Size())
	}
}
