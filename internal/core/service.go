package core

import (
	"container/list"
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

type Dispatcher interface {
	Check(ctx context.Context, req Request) Result
}

type Service struct {
	log        *zap.Logger
	adapters   map[Type]Dispatcher
	results    map[string]Result
	order      *list.List
	maxResults int
	mu         sync.RWMutex
}

func New(log *zap.Logger, maxResults int) *Service {
	if maxResults <= 0 {
		maxResults = 1000
	}
	return &Service{
		adapters:   make(map[Type]Dispatcher),
		log:        log,
		results:    make(map[string]Result),
		order:      list.New(),
		maxResults: maxResults,
	}
}

func (s *Service) Run(ctx context.Context, req Request) Result {
	if req.ID == "" {
		return Result{
			Status: Error,
			Err:    ErrInvalidRequest.Error(),
			At:     time.Now(),
		}
	}

	s.mu.RLock()
	adapter, ok := s.adapters[req.Type]
	s.mu.RUnlock()
	if !ok {
		return Result{
			ID:     req.ID,
			Type:   req.Type,
			Status: Error,
			Err:    fmt.Sprintf("%s: %s", ErrNoAdapter, req.Type),
			At:     time.Now(),
		}
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	result := adapter.Check(ctx, req)
	result.ID = req.ID
	result.Type = req.Type
	result.At = time.Now()
	result.Host = req.Target.Host

	s.log.Info("probe executed",
		zap.String("id", req.ID),
		zap.String("type", string(req.Type)),
		zap.String("status", string(result.Status)),
		zap.Int64("latency_ns", result.Latency.Nanoseconds()),
	)

	s.mu.Lock()
	if elem, exists := s.results[req.ID]; exists {
		_ = elem
	} else if len(s.results) >= s.maxResults {
		if oldest := s.order.Front(); oldest != nil {
			delete(s.results, oldest.Value.(string))
			s.order.Remove(oldest)
		}
	}
	s.results[req.ID] = result
	s.order.PushBack(req.ID)
	s.mu.Unlock()

	return result
}

func (s *Service) Register(t Type, d Dispatcher) {
	s.mu.Lock()
	s.adapters[t] = d
	s.mu.Unlock()
}

func (s *Service) AllResults() []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Result, 0, len(s.results))
	for _, r := range s.results {
		out = append(out, r)
	}
	return out
}

func (s *Service) GetResult(id string) (Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	r, ok := s.results[id]
	return r, ok
}
