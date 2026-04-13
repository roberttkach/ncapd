package api

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func RateLimiterMiddleware(requestsPerSecond float64, burst int, cleanupCtx context.Context) func(http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		buckets = make(map[string]*tokenBucket)
	)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				now := time.Now()
				for ip, b := range buckets {
					b.mu.Lock()
					if now.Sub(b.lastRefill) > 5*time.Minute {
						delete(buckets, ip)
					}
					b.mu.Unlock()
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
			if path == "/healthz" {
				next.ServeHTTP(w, r)
				return
			}

			addr := r.RemoteAddr
			if v := r.Context().Value(ctxRealRemoteAddr); v != nil {
				addr = v.(string)
			}
			ip := extractIP(addr, r.Header)

			mu.Lock()
			bucket, ok := buckets[ip]
			if !ok {
				bucket = newTokenBucket(requestsPerSecond, burst)
				buckets[ip] = bucket
			}
			mu.Unlock()

			if !bucket.allow() {
				retryAfter := int(1.0 / requestsPerSecond)
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractIP(addr string, headers http.Header) string {
	if xff := headers.Get("X-Forwarded-For"); xff != "" {
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			first := strings.TrimSpace(ips[0])
			if ip, _, err := net.SplitHostPort(first); err == nil && ip != "" {
				return ip
			}
			if first != "" {
				return first
			}
		}
	}
	if xri := headers.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

type tokenBucket struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
