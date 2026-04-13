package api_test

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
	"github.com/roberttkach/ncapd/pkg/api"
)

var _ core.Provider = (*mockProvider)(nil)

type mockProvider struct {
	results map[string]core.Result
	status  core.Status
}

func (m *mockProvider) Run(_ context.Context, req core.Request) core.Result {
	s := m.status
	if s == "" {
		s = core.OK
	}
	result := core.Result{
		ID:     req.ID,
		Type:   req.Type,
		Status: s,
		At:     time.Now(),
		Host:   req.Target.Host,
	}
	m.results[req.ID] = result
	return result
}

func (m *mockProvider) AllResults() []core.Result {
	out := make([]core.Result, 0, len(m.results))
	for _, r := range m.results {
		out = append(out, r)
	}
	return out
}

func (m *mockProvider) GetResult(id string) (core.Result, bool) {
	r, ok := m.results[id]
	return r, ok
}

func newTestServer(cfg config.Server, checks []config.Check) *httptest.Server {
	log := zap.NewNop()
	provider := &mockProvider{
		results: map[string]core.Result{
			"test-check": {
				ID:     "test-check",
				Type:   core.TypePortBlock,
				Status: core.OK,
				At:     time.Now(),
				Host:   "example.com",
			},
		},
	}

	srv := api.New(provider, checks, cfg, log)
	return httptest.NewServer(srv.Handler())
}

func newTestServerWithLog(cfg config.Server, checks []config.Check) (*httptest.Server, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	encoder := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	log := zap.New(zapcore.NewCore(encoder, zapcore.AddSync(buf), zap.DebugLevel))

	provider := &mockProvider{
		results: map[string]core.Result{
			"test-check": {
				ID:     "test-check",
				Type:   core.TypePortBlock,
				Status: core.OK,
				At:     time.Now(),
				Host:   "example.com",
			},
		},
	}

	srv := api.New(provider, checks, cfg, log)
	return httptest.NewServer(srv.Handler()), buf
}

func TestIntegration_Healthz(t *testing.T) {
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status 'ok', got %q", body["status"])
	}
}

func TestIntegration_ListChecks(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
		{ID: "check2", Type: core.TypeDNSFilter, Target: core.Target{Host: "google.com"}},
	}
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/checks")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body []api.CheckInfo
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(body) != len(checks) {
		t.Errorf("expected %d checks, got %d", len(checks), len(body))
	}
}

func TestIntegration_Auth_RequiresKey(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr: ":8080",
		Auth: config.Auth{
			Type:   "api_key",
			Keys:   []string{"secret"},
			Header: "X-API-Key",
		},
	}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/checks")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 without API key, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/checks", nil)
	req.Header.Set("X-API-Key", "secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 with API key, got %d", resp.StatusCode)
	}
}

func TestIntegration_PublicPaths_NoAuth(t *testing.T) {
	cfg := config.Server{
		Addr: ":8080",
		Auth: config.Auth{
			Type:   "api_key",
			Keys:   []string{"secret"},
			Header: "X-API-Key",
		},
	}
	srv := newTestServer(cfg, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz: expected status 200, got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("/metrics: expected status 200, got %d", resp.StatusCode)
	}
}

func TestIntegration_RateLimiting(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr: ":8080",
		RateLimit: config.RateLimit{
			Enabled:           true,
			RequestsPerSecond: 10,
			Burst:             2,
		},
	}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	client := &http.Client{}

	for i := 0; i < 2; i++ {
		resp, err := client.Post(srv.URL+"/checks/check1/run", "application/json", nil)
		if err != nil {
			t.Fatalf("request %d failed: %v", i+1, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i+1, resp.StatusCode)
		}
	}

	resp, err := client.Post(srv.URL+"/checks/check1/run", "application/json", nil)
	if err != nil {
		t.Fatalf("rate limit request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", resp.StatusCode)
	}

	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header")
	}
}

func TestIntegration_RunCheck(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.DefaultClient.Post(srv.URL+"/checks/check1/run", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result core.Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ID != "check1" {
		t.Errorf("expected ID 'check1', got %q", result.ID)
	}
	if result.Status != core.OK {
		t.Errorf("expected status OK, got %s", result.Status)
	}
}

func TestIntegration_RunCheck_NotFound(t *testing.T) {
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, nil)
	defer srv.Close()

	resp, err := http.DefaultClient.Post(srv.URL+"/checks/nonexistent/run", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestIntegration_GetResult(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	_, err := http.DefaultClient.Post(srv.URL+"/checks/check1/run", "application/json", nil)
	if err != nil {
		t.Fatalf("run check failed: %v", err)
	}

	resp, err := http.Get(srv.URL + "/results/check1")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var result core.Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.ID != "check1" {
		t.Errorf("expected ID 'check1', got %q", result.ID)
	}
}

func TestIntegration_GetResult_NotFound(t *testing.T) {
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, nil)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/results/does-not-exist")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuditMiddleware(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr:  ":8080",
		Audit: config.Audit{Enabled: true},
	}
	srv, buf := newTestServerWithLog(cfg, checks)
	defer srv.Close()

	resp, err := http.DefaultClient.Post(srv.URL+"/checks/check1/run", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "audit") {
		t.Errorf("expected audit log entry, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "remote_addr") {
		t.Errorf("expected remote_addr in audit log, got: %s", logOutput)
	}
}

func TestIntegration_RunCheck_BlockedStatus(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{Addr: ":8080"}
	log := zap.NewNop()
	provider := &mockProvider{
		results: map[string]core.Result{},
		status:  core.Blocked,
	}
	srv := httptest.NewServer(api.New(provider, checks, cfg, log).Handler())
	defer srv.Close()

	resp, err := http.DefaultClient.Post(srv.URL+"/checks/check1/run", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status 200, got %d", resp.StatusCode)
	}

	var result core.Result
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Status != core.Blocked {
		t.Errorf("expected check status Blocked, got %s", result.Status)
	}
}

func TestIntegration_BearerTokenAuth(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr: ":8080",
		Auth: config.Auth{
			Type:   "bearer_token",
			Keys:   []string{"my-secret-token"},
			Header: "Authorization",
		},
	}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/checks")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 without token, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", srv.URL+"/checks", nil)
	req.Header.Set("Authorization", "Bearer my-secret-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 with bearer token, got %d", resp.StatusCode)
	}

	req2, _ := http.NewRequest("GET", srv.URL+"/checks", nil)
	req2.Header.Set("Authorization", "my-secret-token")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 with bare token, got %d", resp2.StatusCode)
	}

	req3, _ := http.NewRequest("GET", srv.URL+"/checks", nil)
	req3.Header.Set("Authorization", "Bearer wrong-token")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusForbidden {
		t.Errorf("expected status 403 with invalid token, got %d", resp3.StatusCode)
	}

	req4, _ := http.NewRequest("GET", srv.URL+"/checks", nil)
	req4.Header.Set("Authorization", "Bearer")
	resp4, err := http.DefaultClient.Do(req4)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp4.Body.Close()
	if resp4.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 with 'Bearer' only, got %d", resp4.StatusCode)
	}
}

func TestIntegration_ListResults(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{Addr: ":8080"}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/results")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var body []core.Result
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body) != 1 {
		t.Errorf("expected 1 pre-populated result, got %d", len(body))
	}
}

func TestIntegration_UnknownAuthType_Denied(t *testing.T) {
	checks := []config.Check{
		{ID: "check1", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
	}
	cfg := config.Server{
		Addr: ":8080",
		Auth: config.Auth{
			Type:   "unknown_type_xyz",
			Keys:   []string{"secret"},
			Header: "X-API-Key",
		},
	}
	srv := newTestServer(cfg, checks)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/checks")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401 for unknown auth type, got %d", resp.StatusCode)
	}
}
