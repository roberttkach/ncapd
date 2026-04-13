package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

var _ Provider = (*Service)(nil)

var _ Dispatcher = (*mockDispatcher)(nil)

type mockDispatcher struct {
	checkFn func(ctx context.Context, req Request) Result
}

func (m *mockDispatcher) Check(ctx context.Context, req Request) Result {
	if m.checkFn != nil {
		return m.checkFn(ctx, req)
	}
	return Result{Status: OK}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	log := zap.NewNop()
	return New(log, 1000)
}

func TestService_New(t *testing.T) {
	svc := newTestService(t)

	if svc.adapters == nil {
		t.Error("expected adapters map to be initialized")
	}
	if svc.results == nil {
		t.Error("expected results map to be initialized")
	}
	if svc.log == nil {
		t.Error("expected log to be initialized")
	}
}

func TestService_Register(t *testing.T) {
	svc := newTestService(t)
	d := &mockDispatcher{}

	svc.Register(TypePortBlock, d)

	if _, ok := svc.adapters[TypePortBlock]; !ok {
		t.Error("expected adapter to be registered")
	}
}

func TestService_Run(t *testing.T) {
	t.Run("empty request ID returns error", func(t *testing.T) {
		svc := newTestService(t)

		result := svc.Run(context.Background(), Request{})

		if result.Status != Error {
			t.Errorf("status = %s, want Error", result.Status)
		}
	})

	t.Run("no adapter returns error", func(t *testing.T) {
		svc := newTestService(t)

		result := svc.Run(context.Background(), Request{
			ID:   "test-1",
			Type: TypePortBlock,
		})

		if result.Status != Error {
			t.Errorf("status = %s, want Error", result.Status)
		}
		if result.Err == "" {
			t.Error("expected error message for missing adapter")
		}
	})

	t.Run("successful execution", func(t *testing.T) {
		svc := newTestService(t)
		svc.Register(TypePortBlock, &mockDispatcher{
			checkFn: func(_ context.Context, req Request) Result {
				return Result{
					Status:  OK,
					Latency: 5 * time.Millisecond,
					Detail:  "connected",
				}
			},
		})

		result := svc.Run(context.Background(), Request{
			ID:      "test-ok",
			Type:    TypePortBlock,
			Target:  Target{Host: "example.com", Port: 443},
			Timeout: 10 * time.Second,
		})

		if result.Status != OK {
			t.Errorf("status = %s, want OK", result.Status)
		}
		if result.ID != "test-ok" {
			t.Errorf("ID = %q, want 'test-ok'", result.ID)
		}
		if result.Detail != "connected" {
			t.Errorf("detail = %q, want 'connected'", result.Detail)
		}
	})

	t.Run("result is stored", func(t *testing.T) {
		svc := newTestService(t)
		svc.Register(TypePortBlock, &mockDispatcher{
			checkFn: func(_ context.Context, req Request) Result {
				return Result{Status: OK}
			},
		})

		req := Request{ID: "stored-check", Type: TypePortBlock}
		svc.Run(context.Background(), req)

		stored, ok := svc.GetResult("stored-check")
		if !ok {
			t.Fatal("expected result to be stored")
		}
		if stored.Status != OK {
			t.Errorf("stored status = %s, want OK", stored.Status)
		}
	})

	t.Run("timeout context is applied", func(t *testing.T) {
		svc := newTestService(t)
		svc.Register(TypePortBlock, &mockDispatcher{
			checkFn: func(ctx context.Context, _ Request) Result {
				select {
				case <-ctx.Done():
					return Result{Status: Timeout, Err: "context cancelled"}
				case <-time.After(5 * time.Second):
					return Result{Status: OK}
				}
			},
		})

		result := svc.Run(context.Background(), Request{
			ID:      "timeout-test",
			Type:    TypePortBlock,
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != Timeout {
			t.Errorf("status = %s, want Timeout", result.Status)
		}
	})
}

func TestService_AllResults(t *testing.T) {
	svc := newTestService(t)
	svc.Register(TypePortBlock, &mockDispatcher{
		checkFn: func(_ context.Context, req Request) Result {
			return Result{Status: OK}
		},
	})

	svc.Run(context.Background(), Request{ID: "r1", Type: TypePortBlock})
	svc.Run(context.Background(), Request{ID: "r2", Type: TypePortBlock})

	results := svc.AllResults()
	if len(results) < 2 {
		t.Errorf("results = %d, want at least 2", len(results))
	}
}

func TestService_GetResult(t *testing.T) {
	t.Run("existing result", func(t *testing.T) {
		svc := newTestService(t)
		svc.Register(TypePortBlock, &mockDispatcher{
			checkFn: func(_ context.Context, req Request) Result {
				return Result{Status: OK, ID: req.ID}
			},
		})

		svc.Run(context.Background(), Request{ID: "find-me", Type: TypePortBlock})

		r, ok := svc.GetResult("find-me")
		if !ok {
			t.Fatal("expected to find result")
		}
		if r.Status != OK {
			t.Errorf("status = %s, want OK", r.Status)
		}
	})

	t.Run("non-existing result", func(t *testing.T) {
		svc := newTestService(t)

		_, ok := svc.GetResult("does-not-exist")
		if ok {
			t.Error("expected false for non-existing result")
		}
	})
}

func TestService_ConcurrentAccess(t *testing.T) {
	svc := newTestService(t)
	svc.Register(TypePortBlock, &mockDispatcher{
		checkFn: func(_ context.Context, req Request) Result {
			return Result{Status: OK, ID: req.ID}
		},
	})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			id := fmt.Sprintf("%s-%d", t.Name(), n)
			svc.Run(context.Background(), Request{ID: id, Type: TypePortBlock})
		}(i)
	}
	wg.Wait()

	results := svc.AllResults()
	if len(results) != 100 {
		t.Errorf("results after concurrent access = %d, want 100", len(results))
	}
}

func TestService_ConcurrentReadWrite(t *testing.T) {
	svc := newTestService(t)
	svc.Register(TypePortBlock, &mockDispatcher{
		checkFn: func(_ context.Context, req Request) Result {
			return Result{Status: OK, ID: req.ID}
		},
	})

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				id := fmt.Sprintf("write-%d-%d", n, j)
				svc.Run(context.Background(), Request{ID: id, Type: TypePortBlock})
			}
		}(i)
	}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				svc.AllResults()
				svc.GetResult("nonexistent")
			}
		}(i)
	}

	wg.Wait()
}
