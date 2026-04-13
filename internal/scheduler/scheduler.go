package scheduler

import (
	"context"
	"fmt"
	"sync"

	"github.com/robfig/cron/v3"
	"go.uber.org/zap"

	"github.com/roberttkach/ncapd/internal/config"
	"github.com/roberttkach/ncapd/internal/core"
)

type Executor interface {
	Run(ctx context.Context, req core.Request) core.Result
}

type Submitter interface {
	Submit(ctx context.Context, result core.Result) error
}

type Scheduler struct {
	exec     Executor
	sub      Submitter
	log      *zap.Logger
	cron     *cron.Cron
	ctx      context.Context
	cancel   context.CancelFunc
	submitWg sync.WaitGroup
}

func New(exec Executor, sub Submitter, log *zap.Logger) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	c := cron.New(
		cron.WithSeconds(),
		cron.WithLogger(&zapCronLogger{log: log}),
	)
	return &Scheduler{
		exec:   exec,
		sub:    sub,
		log:    log,
		cron:   c,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Scheduler) Register(cfg config.Check) error {
	if cfg.Schedule == "" {
		s.log.Debug("check registered without schedule", zap.String("id", cfg.ID))
		return nil
	}

	req := cfg.ToReq()
	jobID, err := s.cron.AddFunc(cfg.Schedule, func() {
		s.executeJob(req)
	})

	if err != nil {
		return fmt.Errorf("scheduler: register check %q: %w", cfg.ID, err)
	}

	s.log.Info("check scheduled",
		zap.String("id", req.ID),
		zap.String("schedule", cfg.Schedule),
		zap.Int("cron_id", int(jobID)),
	)
	return nil
}

func (s *Scheduler) Start() {
	s.cron.Start()
	s.log.Info("scheduler started")
}

func (s *Scheduler) Shutdown() context.Context {
	s.log.Info("scheduler stopping")
	s.cancel() // Q-H3 fix: cancel all running jobs
	cronCtx := s.cron.Stop()
	<-cronCtx.Done()
	s.submitWg.Wait()
	return cronCtx
}

func (s *Scheduler) executeJob(req core.Request) {
	// Q-H3 fix: use cancellable context instead of context.Background()
	result := s.exec.Run(s.ctx, req)

	switch result.Status {
	case core.Error:
		s.log.Error("check failed",
			zap.String("id", req.ID),
			zap.String("type", string(req.Type)),
			zap.String("err", result.Err),
		)
	case core.Blocked, core.Timeout:
		s.log.Warn("check non-ok",
			zap.String("id", req.ID),
			zap.String("type", string(req.Type)),
			zap.String("status", string(result.Status)),
			zap.Int64("latency_ns", result.Latency.Nanoseconds()),
		)
	default:
		s.log.Debug("check completed",
			zap.String("id", req.ID),
			zap.String("status", string(result.Status)),
			zap.Int64("latency_ns", result.Latency.Nanoseconds()),
		)
	}

	if s.sub != nil {
		s.submitWg.Add(1)
		go func() {
			defer s.submitWg.Done()
			if err := s.sub.Submit(s.ctx, result); err != nil {
				s.log.Debug("scheduled submit failed", zap.Error(err))
			}
		}()
	}
}

type zapCronLogger struct {
	log *zap.Logger
}

func (l *zapCronLogger) Info(msg string, keysAndValues ...interface{}) {
	l.log.Debug("cron", append([]zap.Field{zap.String("msg", msg)}, zapFields(keysAndValues...)...)...)
}

func (l *zapCronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	l.log.Error("cron", append([]zap.Field{zap.Error(err), zap.String("msg", msg)}, zapFields(keysAndValues...)...)...)
}

func zapFields(keysAndValues ...interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(keysAndValues)/2)
	for i := 0; i+1 < len(keysAndValues); i += 2 {
		key, ok := keysAndValues[i].(string)
		if !ok {
			key = fmt.Sprintf("%v", keysAndValues[i])
		}
		fields = append(fields, zap.Any(key, keysAndValues[i+1]))
	}
	return fields
}
