package api

import (
	"bytes"
	"context"
	"encoding/json"
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
	return New(provider, checks, config.Server{Addr: ":0"}, zap.NewNop())
}

func TestServer_healthz(t *testing.T) {
	srv := newTestAPI(&testMockProvider{}, nil)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected 'ok', got %q", body["status"])
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
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body []CheckInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(body))
	}
	if body[0].ID != "c1" || body[1].ID != "c2" {
		t.Errorf("unexpected check IDs: %v", body)
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
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var body []core.Result
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 2 {
		t.Errorf("expected 2 results, got %d", len(body))
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
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var body core.Result
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.ID != "found" {
			t.Errorf("expected ID 'found', got %q", body.ID)
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, nil)

		req := httptest.NewRequest("GET", "/results/missing", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
		}
	})
}

func TestServer_runCheck(t *testing.T) {
	checks := []config.Check{
		{ID: "my-check", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}

	t.Run("existing check → 200", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, checks)

		req := httptest.NewRequest("POST", "/checks/my-check/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}

		var body core.Result
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.ID != "my-check" {
			t.Errorf("expected ID 'my-check', got %q", body.ID)
		}
		if body.Status != core.OK {
			t.Errorf("expected status OK, got %s", body.Status)
		}
	})

	t.Run("unknown check → 404", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, checks)

		req := httptest.NewRequest("POST", "/checks/unknown-id/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
		}
	})

	t.Run("empty checks list → 404", func(t *testing.T) {
		srv := newTestAPI(&testMockProvider{}, nil)

		req := httptest.NewRequest("POST", "/checks/any/run", nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rec.Code)
		}
	})
}

func TestZapMiddleware_LogsRequests(t *testing.T) {
	buf := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(buf), zap.DebugLevel))

	srv := New(&testMockProvider{}, nil, config.Server{Addr: ":0"}, log)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	output := buf.String()
	if !strings.Contains(output, "http_request") {
		t.Errorf("expected 'http_request' in log output, got: %s", output)
	}
	if !strings.Contains(output, `"method":"GET"`) {
		t.Errorf("expected method GET in log, got: %s", output)
	}
	if !strings.Contains(output, `"path":"/healthz"`) {
		t.Errorf("expected path /healthz in log, got: %s", output)
	}
	if !strings.Contains(output, `"status":200`) {
		t.Errorf("expected status 200 in log, got: %s", output)
	}
}
