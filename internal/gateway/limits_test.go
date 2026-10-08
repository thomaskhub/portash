package gateway

import (
	"fmt"
	"testing"
	"time"
)

func TestIPv6GroupedBy64(t *testing.T) {
	if ipKey("2001:db8:1:2::1") != ipKey("2001:db8:1:2:ffff::9") {
		t.Fatal("addresses in one /64 got different keys")
	}
	if ipKey("2001:db8:1:2::1") == ipKey("2001:db8:1:3::1") {
		t.Fatal("different /64s share a key")
	}
	if ipKey("::ffff:192.0.2.1") != "192.0.2.1" {
		t.Fatal("IPv4-mapped address not unmapped")
	}
}

func TestFailLimiterIsBounded(t *testing.T) {
	f := newFailLimiter(10, time.Hour)
	for i := 0; i < 3*maxFailEntries; i++ {
		f.fail(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if len(f.m) > maxFailEntries {
		t.Fatalf("%d entries, want at most %d", len(f.m), maxFailEntries)
	}
}

func TestFailLimiterIsPerIP(t *testing.T) {
	f := newFailLimiter(3, time.Minute)
	for range 3 {
		f.fail("198.51.100.1")
	}
	if !f.blocked("198.51.100.1") {
		t.Fatal("IP over the limit is not blocked")
	}
	if f.blocked("198.51.100.2") {
		t.Fatal("another IP is blocked by someone else's failures")
	}
}
