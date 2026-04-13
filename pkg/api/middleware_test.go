package api

import (
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
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
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
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
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
				t.Errorf("expected status %d, got %d", tt.wantStatus, rec.Code)
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

	publicPaths := []string{"/healthz", "/metrics"}
	for _, path := range publicPaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("path %s: expected status %d, got %d", path, http.StatusOK, rec.Code)
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
		t.Errorf("expected status %d for unknown auth type, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	mw := RateLimiterMiddleware(10, 2)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/checks/test/run", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status %d, got %d", i+1, http.StatusOK, rec.Code)
		}
	}

	req := httptest.NewRequest("POST", "/checks/test/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status %d, got %d", http.StatusTooManyRequests, rec.Code)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header")
	}
}

func newTestLogger() *zap.Logger {
	return zap.NewNop()
}
