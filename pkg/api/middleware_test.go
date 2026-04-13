package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/roberttkach/ncapd/internal/config"
)

func TestAuthMiddleware_None(t *testing.T) {
	cfg := config.Auth{Type: "none"}
	mw := AuthMiddleware(cfg, newTestLogger())

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

func TestAuthMiddleware_APIKey(t *testing.T) {
	cfg := config.Auth{
		Type:   "api_key",
		Keys:   []string{"secret-key-1", "secret-key-2"},
		Header: "X-API-Key",
	}
	mw := AuthMiddleware(cfg, newTestLogger())

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		headerVal  string
		wantStatus int
	}{
		{"valid key", "secret-key-1", http.StatusOK},
		{"valid key 2", "secret-key-2", http.StatusOK},
		{"invalid key", "wrong-key", http.StatusForbidden},
		{"missing key", "", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/checks", nil)
			if tt.headerVal != "" {
				req.Header.Set("X-API-Key", tt.headerVal)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestAuthMiddleware_BearerToken(t *testing.T) {
	cfg := config.Auth{
		Type:   "bearer_token",
		Keys:   []string{"my-token"},
		Header: "Authorization",
	}
	mw := AuthMiddleware(cfg, newTestLogger())

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		headerVal  string
		wantStatus int
	}{
		{"valid bearer", "Bearer my-token", http.StatusOK},
		{"valid bare token", "my-token", http.StatusOK},
		{"invalid token", "Bearer wrong-token", http.StatusForbidden},
		{"missing header", "", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/checks", nil)
			if tt.headerVal != "" {
				req.Header.Set("Authorization", tt.headerVal)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestAuthMiddleware_PublicPaths(t *testing.T) {
	cfg := config.Auth{
		Type:   "api_key",
		Keys:   []string{"secret"},
		Header: "X-API-Key",
	}
	mw := AuthMiddleware(cfg, newTestLogger())

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	publicPaths := []string{"/healthz"}
	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusOK)
			}
		})
	}
}

func TestAuthMiddleware_UnknownType(t *testing.T) {
	cfg := config.Auth{Type: "custom_auth"}
	mw := AuthMiddleware(cfg, newTestLogger())

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/checks", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	mw := RateLimiterMiddleware(10, 2, context.Background())

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/checks/test/run", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}
	}

	req := httptest.NewRequest("POST", "/checks/test/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("missing Retry-After header")
	}
}

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}
