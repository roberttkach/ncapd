package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFilterMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		remoteAddr string
		path       string
		want       int
	}{
		{"allowed", []string{"10.0.0.0/8"}, "10.1.2.3:54321", "/checks", http.StatusOK},
		{"blocked", []string{"10.0.0.0/8"}, "8.8.8.8:12345", "/checks", http.StatusForbidden},
		{"healthz bypass", []string{"10.0.0.0/8"}, "8.8.8.8:12345", "/healthz", http.StatusOK},
		{"healthz trailing slash", []string{"10.0.0.0/8"}, "8.8.8.8:12345", "/healthz/", http.StatusOK},
		{"IPv4-mapped IPv6", []string{"10.0.0.0/8"}, "[::ffff:10.1.2.3]:54321", "/checks", http.StatusOK},
		{"second CIDR match", []string{"10.0.0.0/8", "172.16.0.0/12"}, "172.16.5.1:12345", "/checks", http.StatusOK},
		{"single host", []string{"192.168.1.100/32"}, "192.168.1.100:54321", "/checks", http.StatusOK},
		{"single host miss", []string{"192.168.1.100/32"}, "192.168.1.101:54321", "/checks", http.StatusForbidden},
		{"IPv6 allowed", []string{"::1/128"}, "[::1]:12345", "/checks", http.StatusOK},
		{"IPv6 blocked", []string{"::1/128"}, "[::2]:12345", "/checks", http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := FilterMiddleware(tt.cidrs)
			handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", tt.path, nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestFilterMiddleware_EmptyCIDRs(t *testing.T) {
	mw := FilterMiddleware(nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/checks", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}
