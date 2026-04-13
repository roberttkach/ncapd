package scheduler

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/roberttkach/ncapd/internal/config"
	"github.com/roberttkach/ncapd/internal/core"
)

var _ Executor = (*mockExecutor)(nil)
var _ Submitter = (*mockSubmitter)(nil)

type mockExecutor struct {
	runFn func(ctx context.Context, req core.Request) core.Result
}

func (m *mockExecutor) Run(ctx context.Context, req core.Request) core.Result {
	if m.runFn != nil {
		return m.runFn(ctx, req)
	}
	return core.Result{Status: core.OK}
}

type mockSubmitter struct {
	mu     sync.Mutex
	calls  []core.Result
	submit func(ctx context.Context, result core.Result) error
}

func (m *mockSubmitter) Submit(ctx context.Context, result core.Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, result)
	if m.submit != nil {
		return m.submit(ctx, result)
	}
	return nil
}

func (m *mockSubmitter) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls)
}

func (m *mockSubmitter) LastResult() (core.Result, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.calls) == 0 {
		return core.Result{}, false
	}
	return m.calls[len(m.calls)-1], true
}

func newTestScheduler(t *testing.T) (*Scheduler, *mockExecutor, *mockSubmitter) {
	t.Helper()
	log := zap.NewNop()
	exec := &mockExecutor{}
	sub := &mockSubmitter{}
	sched := New(exec, sub, log)
	return sched, exec, sub
}

func TestScheduler_New(t *testing.T) {
	sched, _, _ := newTestScheduler(t)

	if sched == nil {
		t.Fatal("expected non-nil scheduler")
	}
	if sched.cron == nil {
		t.Fatal("expected cron to be initialized")
	}
}

func TestScheduler_Register(t *testing.T) {
	t.Run("with valid schedule", func(t *testing.T) {
		sched, _, _ := newTestScheduler(t)

		cfg := config.Check{
			ID:       "test-check",
			Type:     core.TypePortBlock,
			Schedule: "0 */5 * * * *",
		}
		err := sched.Register(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty schedule → no error, no job", func(t *testing.T) {
		sched, _, _ := newTestScheduler(t)

		cfg := config.Check{
			ID:       "test-check",
			Type:     core.TypePortBlock,
			Schedule: "",
		}
		err := sched.Register(cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid cron expression → error", func(t *testing.T) {
		sched, _, _ := newTestScheduler(t)

		cfg := config.Check{
			ID:       "test-check",
			Type:     core.TypePortBlock,
			Schedule: "not-a-valid-cron",
		}
		err := sched.Register(cfg)
		if err == nil {
			t.Error("expected error for invalid cron expression")
		}
	})

	t.Run("multiple checks registered", func(t *testing.T) {
		sched, _, _ := newTestScheduler(t)

		checks := []config.Check{
			{ID: "check1", Type: core.TypePortBlock, Schedule: "0 */5 * * * *"},
			{ID: "check2", Type: core.TypeDNSFilter, Schedule: "0 */10 * * * *"},
			{ID: "check3", Type: core.TypeSNIInspect, Schedule: ""},
		}
		for _, ch := range checks {
			err := sched.Register(ch)
			if err != nil {
				t.Fatalf("unexpected error for %s: %v", ch.ID, err)
			}
		}
	})
}

func TestScheduler_StartStop(t *testing.T) {
	sched, _, _ := newTestScheduler(t)

	sched.Start()

	time.Sleep(50 * time.Millisecond)

	ctx := sched.Shutdown()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Error("shutdown timed out")
	}
}

func TestScheduler_ExecuteJob(t *testing.T) {
	t.Run("successful execution logs and submits", func(t *testing.T) {
		sched, exec, sub := newTestScheduler(t)

		exec.runFn = func(_ context.Context, req core.Request) core.Result {
			return core.Result{
				ID:     req.ID,
				Type:   req.Type,
				Status: core.OK,
			}
		}

		sched.executeJob(core.Request{ID: "exec-test", Type: core.TypePortBlock})

		time.Sleep(100 * time.Millisecond)

		if sub.CallCount() != 1 {
			t.Errorf("submit calls = %d, want 1", sub.CallCount())
		}

		last, ok := sub.LastResult()
		if !ok {
			t.Fatal("expected at least one submitted result")
		}
		if last.Status != core.OK {
			t.Errorf("submitted status = %s, want OK", last.Status)
		}
	})

	t.Run("error result submitted", func(t *testing.T) {
		sched, exec, sub := newTestScheduler(t)

		exec.runFn = func(_ context.Context, req core.Request) core.Result {
			return core.Result{
				ID:     req.ID,
				Status: core.Error,
				Err:    "test error",
			}
		}

		sched.executeJob(core.Request{ID: "error-test", Type: core.TypePortBlock})

		time.Sleep(100 * time.Millisecond)

		if sub.CallCount() != 1 {
			t.Errorf("submit calls = %d, want 1", sub.CallCount())
		}

		last, ok := sub.LastResult()
		if !ok {
			t.Fatal("expected at least one submitted result")
		}
		if last.Status != core.Error {
			t.Errorf("submitted status = %s, want Error", last.Status)
		}
	})

	t.Run("nil submitter → no panic", func(t *testing.T) {
		log := zap.NewNop()
		exec := &mockExecutor{
			runFn: func(_ context.Context, req core.Request) core.Result {
				return core.Result{Status: core.OK}
			},
		}
		sched := New(exec, nil, log)

		sched.executeJob(core.Request{ID: "nil-sub", Type: core.TypePortBlock})
		time.Sleep(50 * time.Millisecond)
	})

	t.Run("submit error logged (no panic)", func(t *testing.T) {
		sched, exec, sub := newTestScheduler(t)

		exec.runFn = func(_ context.Context, req core.Request) core.Result {
			return core.Result{Status: core.OK}
		}
		sub.submit = func(_ context.Context, _ core.Result) error {
			return fmt.Errorf("submit failed")
		}

		sched.executeJob(core.Request{ID: "submit-err", Type: core.TypePortBlock})
		time.Sleep(100 * time.Millisecond)
	})
}

func TestScheduler_ZapCronLogger(t *testing.T) {
	log := zap.NewNop()
	zl := &zapCronLogger{log: log}

	zl.Info("test info message", "key", "value")
	zl.Error(fmt.Errorf("test error"), "test error message", "key", "value")
}

func TestScheduler_StartAndScheduledJob(t *testing.T) {
	sched, exec, sub := newTestScheduler(t)

	exec.runFn = func(_ context.Context, req core.Request) core.Result {
		return core.Result{
			ID:     req.ID,
			Type:   req.Type,
			Status: core.OK,
		}
	}

	cfg := config.Check{
		ID:       "cron-test",
		Type:     core.TypePortBlock,
		Schedule: "* * * * * *",
	}
	err := sched.Register(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sched.Start()

	time.Sleep(1500 * time.Millisecond)

	sched.Shutdown()

	if sub.CallCount() < 1 {
		t.Errorf("submit calls = %d, want at least 1", sub.CallCount())
	}
}

func TestScheduler_ShutdownContext(t *testing.T) {
	sched, _, _ := newTestScheduler(t)
	sched.Start()

	ctx := sched.Shutdown()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Error("shutdown context not cancelled within timeout")
	}
}

func TestScheduler_ShutdownWithoutStart(t *testing.T) {
	sched, _, _ := newTestScheduler(t)

	ctx := sched.Shutdown()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Error("shutdown timed out")
	}
}

func TestScheduler_RegisterDuplicateID(t *testing.T) {
	sched, _, _ := newTestScheduler(t)

	cfg := config.Check{
		ID:       "dup",
		Type:     core.TypePortBlock,
		Schedule: "0 */5 * * * *",
	}
	if err := sched.Register(cfg); err != nil {
		t.Fatalf("first register: unexpected error: %v", err)
	}

	if err := sched.Register(cfg); err != nil {
		t.Fatalf("second register: unexpected error: %v", err)
	}
}
