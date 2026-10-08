package totp

import (
	"errors"
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, truncated to 6 digits).
func TestRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := Code(secret, ts/Period); got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
	}
}

func TestStoreReplayAndLockout(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := Store{Dir: t.TempDir(), Now: func() time.Time { return now }}
	if _, err := s.Enroll("alice", "portash"); err != nil {
		t.Fatal(err)
	}
	sec, _ := s.secret("alice")
	code := Code(sec, Step(now))
	if err := s.Check("alice", code); err != nil {
		t.Fatalf("valid code refused: %v", err)
	}
	if err := s.Check("alice", code); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed code accepted: %v", err)
	}
	// A code from the previous step is also refused once a newer one was used.
	if err := s.Check("alice", Code(sec, Step(now)-1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("older code accepted: %v", err)
	}
	for i := 0; i < MaxFails; i++ {
		s.Check("alice", "000000")
	}
	now = now.Add(Period * time.Second)
	if err := s.Check("alice", Code(sec, Step(now))); !errors.Is(err, ErrLocked) {
		t.Fatalf("want lockout, got %v", err)
	}
	now = now.Add(Lockout)
	if err := s.Check("alice", Code(sec, Step(now))); err != nil {
		t.Fatalf("lockout didn't expire: %v", err)
	}
	if err := s.Check("bob", "123456"); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("want no secret, got %v", err)
	}
	if err := s.Check("../etc", "123456"); err == nil {
		t.Fatal("path traversal user accepted")
	}
}
