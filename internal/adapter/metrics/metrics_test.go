package metrics

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

var _ core.Dispatcher = (*mockDispatcher)(nil)
var _ core.Dispatcher = (*mockDispatcherFunc)(nil)

type mockDispatcher struct {
	result core.Result
}

func (m *mockDispatcher) Check(_ context.Context, _ core.Request) core.Result {
	return m.result
}

func TestDecorator_New(t *testing.T) {
	d := NewDecorator(&mockDispatcher{})
	if d == nil {
		t.Fatal("expected non-nil decorator")
	}
}

func TestDecorator_Check_RecordsMetrics(t *testing.T) {
	decorator := newTestDecorator()

	req := core.Request{
		ID:   "metrics-verify",
		Type: core.TypePortBlock,
	}

	result := decorator.Check(context.Background(), req)

	if result.Status != core.OK {
		t.Errorf("expected status OK, got %s", result.Status)
	}

	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()

	if !strings.Contains(body, `ncapd_check_total`) || !strings.Contains(body, `metrics-verify`) {
		t.Error("expected ncapd_check_total counter with check_id='metrics-verify'")
	}
	if !strings.Contains(body, `ncapd_check_blocked`) || !strings.Contains(body, `metrics-verify`) {
		t.Error("expected ncapd_check_blocked gauge with check_id='metrics-verify'")
	}
	if !strings.Contains(body, `ncapd_check_duration_seconds`) || !strings.Contains(body, `metrics-verify`) {
		t.Error("expected ncapd_check_duration_seconds histogram with check_id='metrics-verify'")
	}
}

func TestDecorator_Check_BlockedStatus(t *testing.T) {
	decorator := newTestDecoratorWithResult(core.Result{
		Status: core.Blocked,
		Err:    "connection refused",
	})

	req := core.Request{
		ID:   "blocked-check",
		Type: core.TypePortBlock,
	}

	result := decorator.Check(context.Background(), req)

	if result.Status != core.Blocked {
		t.Errorf("expected status Blocked, got %s", result.Status)
	}
}

func TestDecorator_Check_WithThroughput(t *testing.T) {
	decorator := newTestDecoratorWithResult(core.Result{
		Status:     core.OK,
		Throughput: 5000.0,
	})

	req := core.Request{
		ID:   "throughput-check",
		Type: core.TypeThrottle,
	}

	result := decorator.Check(context.Background(), req)

	if result.Throughput != 5000.0 {
		t.Errorf("expected throughput 5000.0, got %f", result.Throughput)
	}
}

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "ncapd_check_total") {
		t.Error("expected ncapd_check_total metric in response")
	}
}

func TestHandler_ContentType(t *testing.T) {
	handler := Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("expected text/plain content type, got %q", contentType)
	}
}

func TestHandler_ProducesValidOutput(t *testing.T) {
	handler := Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()
	if len(body) == 0 {
		t.Error("expected non-empty metrics output")
	}
}

func TestRecordMetrics_Labels(t *testing.T) {
	tests := []struct {
		name   string
		result core.Result
	}{
		{
			name:   "OK status",
			result: core.Result{Status: core.OK, Latency: 10 * time.Millisecond},
		},
		{
			name:   "Blocked status",
			result: core.Result{Status: core.Blocked, Latency: 5 * time.Millisecond},
		},
		{
			name:   "Error status",
			result: core.Result{Status: core.Error, Latency: 1 * time.Millisecond, Err: "test error"},
		},
		{
			name:   "Timeout status",
			result: core.Result{Status: core.Timeout, Latency: 100 * time.Millisecond},
		},
		{
			name:   "with throughput",
			result: core.Result{Status: core.OK, Latency: 50 * time.Millisecond, Throughput: 1024.0},
		},
		{
			name:   "zero throughput",
			result: core.Result{Status: core.OK, Latency: 10 * time.Millisecond, Throughput: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordMetrics("test-id", "test-type", tt.result)
		})
	}
}

func TestDecorator_Check_CallsInnerDispatcher(t *testing.T) {
	called := false
	inner := &mockDispatcherFunc{
		checkFn: func(_ context.Context, req core.Request) core.Result {
			called = true
			return core.Result{Status: core.OK, ID: req.ID}
		},
	}

	d := NewDecorator(inner)
	req := core.Request{ID: "call-test", Type: core.TypePortBlock}
	d.Check(context.Background(), req)

	if !called {
		t.Error("expected inner dispatcher to be called")
	}
}

func TestHandler_PrometheusFormat(t *testing.T) {
	d := NewDecorator(&mockDispatcher{
		result: core.Result{Status: core.OK, Latency: 5 * time.Millisecond},
	})
	d.Check(context.Background(), core.Request{ID: "fmt-test", Type: core.TypePortBlock})

	handler := Handler()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	body := rec.Body.String()

	if !strings.Contains(body, "ncapd_check_total") {
		t.Error("missing ncapd_check_total in metrics output")
	}
	if !strings.Contains(body, "ncapd_check_duration_seconds") {
		t.Error("missing ncapd_check_duration_seconds in metrics output")
	}
	if !strings.Contains(body, "ncapd_check_blocked") {
		t.Error("missing ncapd_check_blocked in metrics output")
	}
}

func TestMetrics_NoPanicOnEmptyResult(t *testing.T) {
	recordMetrics("", "", core.Result{})
}

func TestHandler_DirectHTTPAccess(t *testing.T) {
	handler := Handler()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Error("expected non-empty response body")
	}
}

func newTestDecorator() *Decorator {
	return NewDecorator(&mockDispatcher{
		result: core.Result{Status: core.OK, Latency: 10 * time.Millisecond},
	})
}

func newTestDecoratorWithResult(result core.Result) *Decorator {
	return NewDecorator(&mockDispatcher{result: result})
}

type mockDispatcherFunc struct {
	checkFn func(context.Context, core.Request) core.Result
}

func (m *mockDispatcherFunc) Check(ctx context.Context, req core.Request) core.Result {
	return m.checkFn(ctx, req)
}
