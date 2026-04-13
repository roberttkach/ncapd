package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// AuthFailureLimiterMiddleware tracks auth failures per IP.
// After maxFailures within windowSeconds, returns 429 for banSeconds.
func AuthFailureLimiterMiddleware(maxFailures, windowSeconds, banSeconds int, cleanupCtx context.Context) func(http.Handler) http.Handler {
	window := time.Duration(windowSeconds) * time.Second
	banDur := time.Duration(banSeconds) * time.Second

	var (
		mu    sync.Mutex
		data  = make(map[string]*authEntry)
		stale = time.Duration(windowSeconds+banSeconds) * time.Second
	)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for ip, e := range data {
					e.mu.Lock()
					lastBanned := now.Sub(e.bannedUntil) > stale
					e.mu.Unlock()
					if lastBanned {
						delete(data, ip)
					}
				}
				mu.Unlock()
			case <-cleanupCtx.Done():
				return
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			if path != "/" && path[len(path)-1] == '/' {
				path = path[:len(path)-1]
			}
			if publicPaths[path] {
				next.ServeHTTP(w, r)
				return
			}

			addr := r.RemoteAddr
			if v := r.Context().Value(ctxRealRemoteAddr); v != nil {
				addr = v.(string)
			}
			ip := extractIP(addr, r.Header)

			mu.Lock()
			e, ok := data[ip]
			if !ok {
				e = &authEntry{}
				data[ip] = e
			}
			mu.Unlock()

			e.mu.Lock()
			if time.Now().Before(e.bannedUntil) {
				retry := int(e.bannedUntil.Sub(time.Now()).Seconds()) + 1
				e.mu.Unlock()
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "too many auth failures"})
				return
			}
			e.mu.Unlock()

			ww := &authStatusWriter{w: w}
			next.ServeHTTP(ww, r)

			if ww.status == http.StatusUnauthorized || ww.status == http.StatusForbidden {
				e.recordFailure(maxFailures, window, banDur)
			}
		})
	}
}

type authEntry struct {
	mu          sync.Mutex
	failures    []time.Time
	bannedUntil time.Time
}

func (e *authEntry) recordFailure(max int, window, banDur time.Duration) {
	now := time.Now()
	cutoff := now.Add(-window)
	i := 0
	for i < len(e.failures) && e.failures[i].Before(cutoff) {
		i++
	}
	e.failures = e.failures[i:]
	e.failures = append(e.failures, now)

	if len(e.failures) >= max {
		e.bannedUntil = now.Add(banDur)
		e.failures = nil
	}
}

type authStatusWriter struct {
	w      http.ResponseWriter
	status int
}

func (w *authStatusWriter) Header() http.Header { return w.w.Header() }
func (w *authStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.w.Write(b)
}
func (w *authStatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.w.WriteHeader(code)
}
