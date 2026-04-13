package api

import (
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/roberttkach/ncapd/internal/config"
)

var publicPaths = map[string]bool{
	"/healthz": true,
	"/metrics": true,
}

func AuthMiddleware(cfg config.Auth, log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := strings.TrimSuffix(r.URL.Path, "/")
			if publicPaths[path] {
				next.ServeHTTP(w, r)
				return
			}

			switch cfg.Type {
			case "none", "":
				next.ServeHTTP(w, r)
				return

			case "api_key":
				key := r.Header.Get(cfg.Header)
				if key == "" {
					writeError(w, http.StatusUnauthorized, "missing API key")
					return
				}
				if !cfg.CheckKey(key) {
					writeError(w, http.StatusForbidden, "invalid API key")
					return
				}

			case "bearer_token":
				auth := r.Header.Get(cfg.Header)
				if auth == "" {
					writeError(w, http.StatusUnauthorized, "missing authorization header")
					return
				}
				// Support "Bearer <token>" format
				token := auth
				if strings.HasPrefix(auth, "Bearer ") {
					token = strings.TrimPrefix(auth, "Bearer ")
				} else if strings.HasPrefix(auth, "Bearer") {
					writeError(w, http.StatusUnauthorized, "invalid authorization header format")
					return
				}
				if token == "" {
					writeError(w, http.StatusUnauthorized, "invalid authorization header format")
					return
				}
				if !cfg.CheckKey(token) {
					writeError(w, http.StatusForbidden, "invalid token")
					return
				}

			default:
				log.Warn("unknown auth type, denying request", zap.String("type", cfg.Type))
				writeError(w, http.StatusUnauthorized, "unsupported auth type")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
