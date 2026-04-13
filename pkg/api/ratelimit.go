package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func RateLimiterMiddleware(requestsPerSecond float64, burst int) func(http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		buckets = make(map[string]*tokenBucket)
	)

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
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
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr := r.RemoteAddr
			if v := r.Context().Value(ctxRealRemoteAddr); v != nil {
				addr = v.(string)
			}
			ip := extractIP(addr)

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

func extractIP(addr string) string {
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
