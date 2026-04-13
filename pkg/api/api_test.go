package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/roberttkach/ncapd/internal/config"
	"github.com/roberttkach/ncapd/internal/core"
)

var _ core.Provider = (*testMockProvider)(nil)

type testMockProvider struct {
	results map[string]core.Result
	all     []core.Result
}

func (m *testMockProvider) Run(_ context.Context, req core.Request) core.Result {
	r := core.Result{ID: req.ID, Type: req.Type, Status: core.OK, At: time.Now()}
	if m.results != nil {
		m.results[req.ID] = r
	}
	return r
}

func (m *testMockProvider) AllResults() []core.Result {
	if m.all != nil {
		return m.all
	}
	return []core.Result{}
}

func (m *testMockProvider) GetResult(id string) (core.Result, bool) {
	if m.results == nil {
		return core.Result{}, false
	}
	r, ok := m.results[id]
	return r, ok
}

func newTestAPI(provider core.Provider, checks []config.Check) *Server {
	srv, err := New(provider, checks, config.Server{Addr: ":0"}, zap.NewNop())
	if err != nil {
		panic(fmt.Sprintf("api.New failed: %v", err))
	}
	return srv
}

func TestServer_healthz(t *testing.T) {
	srv := newTestAPI(&testMockProvider{}, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
}

func TestServer_listChecks(t *testing.T) {
	checks := []config.Check{
		{ID: "c1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}, Schedule: "0 */5 * * * *"},
		{ID: "c2", Type: core.TypeDNSFilter, Target: core.Target{Host: "google.com"}},
	}
	srv := newTestAPI(&testMockProvider{}, checks)

	req := httptest.NewRequest("GET", "/checks", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body []CheckInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("checks = %d, want 2", len(body))
	}
	if body[0].ID != "c1" || body[1].ID != "c2" {
		t.Errorf("check IDs = %v, want [c1 c2]", body)
	}
}

func TestServer_listResults(t *testing.T) {
	srv := newTestAPI(&testMockProvider{
		all: []core.Result{
			{ID: "r1", Type: core.TypePortBlock, Status: core.OK},
			{ID: "r2", Type: core.TypeDNSFilter, Status: core.Blocked},
		},
	}, nil)

	req := httptest.NewRequest("GET", "/results", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body []core.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("results = %d, want 2", len(body))
	}
}

func TestServer_getResult(t *testing.T) {
	t.Run("existing", func(t *testing.T) {
		results := map[string]core.Result{
			"found": {ID: "found", Type: core.TypePortBlock, Status: core.OK},
		}
		srv := newTestAPI(&testMockProvider{results: results}, nil)

		req := httptest.NewRequest("GET", "/results/found", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var body core.Result
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.ID != "found" {
			t.Errorf("ID = %q, want %q", body.ID, "found")
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, nil)

		req := httptest.NewRequest("GET", "/results/missing", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestServer_runCheck(t *testing.T) {
	checks := []config.Check{
		{ID: "my-check", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}

	t.Run("existing check", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, checks)

		req := httptest.NewRequest("POST", "/checks/my-check/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		var body core.Result
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.ID != "my-check" {
			t.Errorf("ID = %q, want %q", body.ID, "my-check")
		}
		if body.Status != core.OK {
			t.Errorf("status = %s, want %s", body.Status, core.OK)
		}
	})

	t.Run("unknown check", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, checks)

		req := httptest.NewRequest("POST", "/checks/unknown-id/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("empty checks list", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, nil)

		req := httptest.NewRequest("POST", "/checks/any/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("rapid re-run", func(t *testing.T) {
		srv, err := New(&testMockProvider{}, checks, config.Server{
			Addr: ":0", RunCooldown: config.Duration(10 * time.Second),
		}, zap.NewNop())
		if err != nil {
			t.Fatalf("api.New failed: %v", err)
		}

		req := httptest.NewRequest("POST", "/checks/my-check/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}

		req = httptest.NewRequest("POST", "/checks/my-check/run", nil)
		rec = httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
		}
	})
}

func TestZapMiddleware_LogsRequests(t *testing.T) {
	buf := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(buf), zap.DebugLevel))

	srv, err := New(&testMockProvider{}, nil, config.Server{Addr: ":0"}, log)
	if err != nil {
		t.Fatalf("api.New failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "http_request") {
		t.Errorf("log missing http_request")
	}
	if !strings.Contains(output, `"method":"GET"`) {
		t.Errorf("log missing method GET")
	}
	if !strings.Contains(output, `"path":"/healthz"`) {
		t.Errorf("log missing path /healthz")
	}
	if !strings.Contains(output, `"status":200`) {
		t.Errorf("log missing status 200")
	}
}

func TestAuditMiddleware_LogsRemoteAddr(t *testing.T) {
	buf := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(buf), zap.DebugLevel))

	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	srv, err := New(&testMockProvider{}, checks, config.Server{
		Addr:  ":0",
		Audit: config.Audit{Enabled: true},
	}, log)
	if err != nil {
		t.Fatalf("api.New failed: %v", err)
	}

	req := httptest.NewRequest("POST", "/checks/check1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	output := buf.String()
	if !strings.Contains(output, "audit") {
		t.Errorf("log missing audit entry")
	}
	if !strings.Contains(output, "remote_addr") {
		t.Errorf("log missing remote_addr")
	}
}

func TestServer_RunCheck_BlockedStatus(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	srv := &Server{
		svc:        &mockProviderBlocked{},
		checks:     checks,
		checksByID: map[string]*config.Check{"check1": &checks[0]},
		log:        zap.NewNop(),
		cfg:        config.Server{Addr: ":0"},
		lastRun:    make(map[string]time.Time),
	}
	srv.mux = srv.buildRouter()

	req := httptest.NewRequest("POST", "/checks/check1/run", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result core.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Status != core.Blocked {
		t.Errorf("status = %s, want %s", result.Status, core.Blocked)
	}
}

type mockProviderBlocked struct{}

func (m *mockProviderBlocked) Run(_ context.Context, req core.Request) core.Result {
	return core.Result{ID: req.ID, Type: req.Type, Status: core.Blocked, At: time.Now()}
}
func (m *mockProviderBlocked) AllResults() []core.Result { return nil }
func (m *mockProviderBlocked) GetResult(_ string) (core.Result, bool) {
	return core.Result{}, false
}

func TestServer_BearerTokenAuth(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr: ":0",
		Auth: config.Auth{
			Type:   "bearer_token",
			Keys:   []string{"my-secret-token"},
			Header: "Authorization",
		},
	}
	srv, err := New(&testMockProvider{}, checks, cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("api.New failed: %v", err)
	}

	tests := []struct {
		name       string
		headerVal  string
		wantStatus int
	}{
		{"valid bearer", "Bearer my-secret-token", http.StatusOK},
		{"valid bare token", "my-secret-token", http.StatusOK},
		{"invalid token", "Bearer wrong-token", http.StatusForbidden},
		{"missing header", "", http.StatusUnauthorized},
		{"empty bearer", "Bearer ", http.StatusUnauthorized},
		{"Bearer only", "Bearer", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/checks", nil)
			if tt.headerVal != "" {
				req.Header.Set("Authorization", tt.headerVal)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
