package api

import (
	"net/http"
	"testing"
)

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		headers http.Header
		want    string
	}{
		{"IPv4 with port, no headers", "192.168.1.1:8080", nil, "192.168.1.1"},
		{"IPv6 with port, no headers", "[::1]:80", nil, "::1"},
		{"bare IPv4, no headers", "192.168.1.1", nil, "192.168.1.1"},
		{"bare IPv6, no headers", "::1", nil, "::1"},
		{"empty, no headers", "", nil, ""},
		{"localhost with port, no headers", "127.0.0.1:12345", nil, "127.0.0.1"},
		{"X-Forwarded-For single", "10.0.0.1:80", http.Header{"X-Forwarded-For": []string{"203.0.113.5"}}, "203.0.113.5"},
		{"X-Forwarded-For chain", "10.0.0.1:80", http.Header{"X-Forwarded-For": []string{"203.0.113.5, 198.51.100.10"}}, "203.0.113.5"},
		{"X-Real-IP fallback", "10.0.0.1:80", http.Header{"X-Real-Ip": []string{"192.0.2.1"}}, "192.0.2.1"},
		{"X-Forwarded-For overrides X-Real-IP", "10.0.0.1:80", http.Header{"X-Forwarded-For": []string{"203.0.113.5"}, "X-Real-Ip": []string{"192.0.2.1"}}, "203.0.113.5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractIP(tt.addr, tt.headers)
			if got != tt.want {
				t.Errorf("extractIP(%q, %v) = %q, want %q", tt.addr, tt.headers, got, tt.want)
			}
		})
	}
}
