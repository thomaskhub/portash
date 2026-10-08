package main

import "testing"

func TestCheckTunnelFlags(t *testing.T) {
	cases := []struct {
		name, listen, header string
		anyAddr, wantErr     bool
	}{
		{"no tunnel", "", "", false, false},
		{"loopback with header", "127.0.0.1:8080", "CF-Connecting-IP", false, false},
		{"ipv6 loopback", "[::1]:8080", "X-Real-IP", false, false},
		{"localhost", "localhost:8080", "X-Real-IP", false, false},
		{"missing header", "127.0.0.1:8080", "", false, true},
		{"all interfaces", "0.0.0.0:8080", "CF-Connecting-IP", false, true},
		{"empty host", ":8080", "CF-Connecting-IP", false, true},
		{"public address", "203.0.113.5:8080", "CF-Connecting-IP", false, true},
		{"override", "0.0.0.0:8080", "CF-Connecting-IP", true, false},
		{"override still needs header", "0.0.0.0:8080", "", true, true},
		{"no port", "127.0.0.1", "CF-Connecting-IP", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkTunnelFlags(c.listen, c.header, c.anyAddr)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkTunnelFlags(%q, %q, %v) = %v, wantErr %v", c.listen, c.header, c.anyAddr, err, c.wantErr)
			}
		})
	}
}
