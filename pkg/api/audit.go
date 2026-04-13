package api

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"
)

func AuditMiddleware(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(ww, r)

			fields := []zap.Field{
				zap.String("remote_addr", extractIP(r.RemoteAddr, r.Header)),
				zap.String("user_agent", r.UserAgent()),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
			}
			if ww.Status() >= 400 {
				log.Warn("audit", fields...)
			} else {
				log.Info("audit", fields...)
			}
		})
	}
}
