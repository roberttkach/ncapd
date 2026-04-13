package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthFailureLimiterMiddleware(t *testing.T) {
	t.Run("ban after max failures", func(t *testing.T) {
		mw := AuthFailureLimiterMiddleware(3, 60, 10, context.Background())
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))

		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/checks", nil)
			req.RemoteAddr = "1.2.3.4:12345"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("failure %d: status = %d, want %d", i+1, rec.Code, http.StatusForbidden)
			}
		}

		req := httptest.NewRequest("GET", "/checks", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
		if rec.Header().Get("Retry-After") == "" {
			t.Error("missing Retry-After header")
		}
	})

	t.Run("different IP unaffected", func(t *testing.T) {
		mw := AuthFailureLimiterMiddleware(2, 60, 10, context.Background())
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest("GET", "/checks", nil)
		req.RemoteAddr = "5.6.7.8:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("401 and 403 both counted", func(t *testing.T) {
		mw := AuthFailureLimiterMiddleware(2, 60, 10, context.Background())

		h401 := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		h403 := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))

		req := httptest.NewRequest("GET", "/checks", nil)
		req.RemoteAddr = "9.9.9.9:12345"

		rec := httptest.NewRecorder()
		h401.ServeHTTP(rec, req)
		rec = httptest.NewRecorder()
		h403.ServeHTTP(rec, req)

		// 3rd → 429 (maxFailures = 2)
		rec = httptest.NewRecorder()
		h401.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
	})
}
