package api

import "testing"

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"IPv4 with port", "192.168.1.1:8080", "192.168.1.1"},
		{"IPv6 with port", "[::1]:80", "::1"},
		{"bare IPv4", "192.168.1.1", "192.168.1.1"},
		{"bare IPv6", "::1", "::1"},
		{"empty", "", ""},
		{"localhost with port", "127.0.0.1:12345", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIP(tt.addr)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
