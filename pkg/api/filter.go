package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
)

// FilterMiddleware restricts access to protected routes by source IP.
// /healthz is always allowed. CIDR validation is done at config load time.
func FilterMiddleware(cidrs []string) func(http.Handler) http.Handler {
	if len(cidrs) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, _ := netip.ParsePrefix(c)
		prefixes = append(prefixes, p)
	}

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
			rawIP := extractIP(addr, r.Header)

			ip, err := netip.ParseAddr(rawIP)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "source IP not allowed"})
				return
			}
			ip = ip.Unmap()

			for _, p := range prefixes {
				if p.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "source IP not allowed"})
		})
	}
}
