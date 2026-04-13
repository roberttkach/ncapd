package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/roberttkach/ncapd/internal/adapter/metrics"
	"github.com/roberttkach/ncapd/internal/config"
	"github.com/roberttkach/ncapd/internal/core"
	"github.com/roberttkach/ncapd/internal/validate"
)

type Server struct {
	svc           core.Provider
	log           *zap.Logger
	checks        []config.Check
	checksByID    map[string]*config.Check
	mux           *chi.Mux
	srv           *http.Server
	cfg           config.Server
	lastRunMu     sync.RWMutex
	lastRun       map[string]time.Time
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
}

type CheckInfo struct {
	ID       string    `json:"id"`
	Type     core.Type `json:"type"`
	Schedule string    `json:"schedule,omitempty"`
}

func New(svc core.Provider, checks []config.Check, serverCfg config.Server, log *zap.Logger) (*Server, error) {
	checksByID := make(map[string]*config.Check, len(checks))
	for i := range checks {
		checksByID[checks[i].ID] = &checks[i]
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		svc:           svc,
		log:           log,
		checks:        checks,
		checksByID:    checksByID,
		cfg:           serverCfg,
		lastRun:       make(map[string]time.Time),
		cleanupCtx:    ctx,
		cleanupCancel: cancel,
	}
	s.mux = s.buildRouter()
	s.srv = &http.Server{
		Addr:         serverCfg.Addr,
		Handler:      s.mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if serverCfg.TLS.Enabled() {
		tlsCfg, err := buildTLSConfig(serverCfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("api: build TLS config: %w", err)
		}
		s.srv.TLSConfig = tlsCfg
	}

	return s, nil
}

func (s *Server) Start() error {
	if s.cfg.TLS.Enabled() {
		s.log.Info("API server listening with TLS", zap.String("addr", s.srv.Addr))
		return s.srv.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	}
	s.log.Info("API server listening", zap.String("addr", s.srv.Addr))
	return s.srv.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("API server shutting down")
	s.cleanupCancel()
	return s.srv.Shutdown(ctx)
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) listResults(w http.ResponseWriter, _ *http.Request) {
	if err := writeJSON(w, http.StatusOK, s.svc.AllResults()); err != nil {
		s.log.Error("writeJSON failed", zap.Error(err))
	}
}

func (s *Server) getResult(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	result, ok := s.svc.GetResult(id)
	if !ok {
		writeError(w, http.StatusNotFound, "no result for id")
		return
	}
	if err := writeJSON(w, http.StatusOK, result); err != nil {
		s.log.Error("writeJSON failed", zap.Error(err))
	}
}

func (s *Server) runCheck(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cfg, ok := s.checksByID[id]
	if !ok {
		writeError(w, http.StatusNotFound, "check not found")
		return
	}

	if !s.checkCooldown(id) {
		writeError(w, http.StatusTooManyRequests, "check is in cooldown period")
		return
	}

	if err := validateTargetHandler(cfg.Target, cfg.Type, id, s.log); err != nil {
		writeError(w, http.StatusBadRequest, "invalid check target")
		return
	}

	result := s.executeCheckHandler(r.Context(), cfg.ToReq())

	s.recordLastRun(id)

	if err := writeJSON(w, http.StatusOK, result); err != nil {
		s.log.Error("writeJSON failed", zap.Error(err))
	}
}

func (s *Server) checkCooldown(id string) bool {
	s.lastRunMu.RLock()
	last, ok := s.lastRun[id]
	s.lastRunMu.RUnlock()
	cooldown := time.Duration(s.cfg.RunCooldown)
	return !ok || time.Since(last) >= cooldown
}

func (s *Server) recordLastRun(id string) {
	s.lastRunMu.Lock()
	s.lastRun[id] = time.Now()
	s.lastRunMu.Unlock()
}

func validateTargetHandler(target core.Target, checkType core.Type, checkID string, log *zap.Logger) error {
	if err := validate.Target(target, checkType); err != nil {
		log.Error("invalid check target", zap.String("id", checkID), zap.Error(err))
		return err
	}
	return nil
}

func (s *Server) executeCheckHandler(ctx context.Context, req core.Request) core.Result {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.svc.Run(ctx, req)
}

func (s *Server) listChecks(w http.ResponseWriter, _ *http.Request) {
	out := make([]CheckInfo, len(s.checks))
	for i, c := range s.checks {
		out[i] = CheckInfo{
			ID:       c.ID,
			Type:     c.Type,
			Schedule: c.Schedule,
		}
	}
	if err := writeJSON(w, http.StatusOK, out); err != nil {
		s.log.Error("writeJSON failed", zap.Error(err))
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if err := writeJSON(w, http.StatusOK, map[string]string{"status": "ok"}); err != nil {
		s.log.Error("writeJSON failed", zap.Error(err))
	}
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(realIPCapture)
	r.Use(zapMiddleware(s.log))
	r.Use(middleware.Recoverer)
	r.Use(FilterMiddleware(s.cfg.AllowedSourceIPs))
	r.Use(AuthMiddleware(s.cfg.Auth, s.log))
	if s.cfg.AuthRateLimit.Enabled {
		r.Use(AuthFailureLimiterMiddleware(
			s.cfg.AuthRateLimit.MaxFailures,
			s.cfg.AuthRateLimit.WindowSeconds,
			s.cfg.AuthRateLimit.BanSeconds,
			s.cleanupCtx,
		))
	}
	if s.cfg.Audit.Enabled {
		r.Use(AuditMiddleware(s.log))
	}

	r.Get("/healthz", s.healthz)

	r.Group(func(r chi.Router) {
		if s.cfg.RateLimit.Enabled {
			r.Use(RateLimiterMiddleware(
				s.cfg.RateLimit.RequestsPerSecond,
				s.cfg.RateLimit.Burst,
				s.cleanupCtx,
			))
		}
		r.Handle("/metrics", metrics.Handler())
		r.Post("/checks/{id}/run", s.runCheck)
		r.Get("/results", s.listResults)
		r.Get("/results/{id}", s.getResult)
		r.Get("/checks", s.listChecks)
	})

	return r
}

type contextKey struct{ name string }

var ctxRealRemoteAddr = contextKey{"real_remote_addr"}

func realIPCapture(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxRealRemoteAddr, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeError(w http.ResponseWriter, code int, message string) {
	_ = writeJSON(w, code, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, code int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode JSON response: %w", err)
	}
	return nil
}

func zapMiddleware(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			start := time.Now()

			next.ServeHTTP(ww, r)

			log.Info("http_request",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", ww.Status()),
				zap.Duration("latency_ms", time.Since(start)),
				zap.String("request_id", middleware.GetReqID(r.Context())),
			)
		})
	}
}

func buildTLSConfig(tlsCfg config.TLS) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load server cert: %w", err)
	}

	tc := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if tlsCfg.ClientCAFile != "" {
		caCert, err := os.ReadFile(tlsCfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls: read client CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("tls: failed to parse client CA cert")
		}
		tc.ClientCAs = caCertPool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tc, nil
}
