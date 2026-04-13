package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/roberttkach/ncapd/internal/adapter/http"
	"github.com/roberttkach/ncapd/internal/adapter/master"
	"github.com/roberttkach/ncapd/internal/adapter/metrics"
	"github.com/roberttkach/ncapd/internal/adapter/net"
	"github.com/roberttkach/ncapd/internal/adapter/tls"
	"github.com/roberttkach/ncapd/internal/config"
	"github.com/roberttkach/ncapd/internal/core"
	"github.com/roberttkach/ncapd/internal/scheduler"
	"github.com/roberttkach/ncapd/pkg/api"
)

func main() {
	var allowInsecureMaster = flag.Bool("allow-insecure-master", false, "allow gRPC master connection with InsecureSkipVerify")
	var allowInsecureHTTP = flag.Bool("allow-insecure-http", false, "allow HTTP probes with InsecureSkipVerify (MITM risk)")

	cfgPath := flag.String("config", "/etc/ncapd/config.json", "path to JSON config")
	flag.Parse()

	cfg, warnings, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	log := buildLogger(cfg.Log.Level)
	defer log.Sync()

	for _, w := range warnings {
		log.Warn("config", zap.String("warning", w))
	}

	logStartInfo(log, cfg)

	if cfg.Server.MasterTLS.InsecureSkipVerify && !*allowInsecureMaster {
		log.Fatal("master TLS: InsecureSkipVerify is enabled (use --allow-insecure-master to override)")
	}
	if cfg.Server.SkipVerify != nil && *cfg.Server.SkipVerify && !*allowInsecureHTTP {
		log.Fatal("HTTP probes: skip_verify is enabled (use --allow-insecure-http to override)")
	}

	svc := core.New(log, *cfg.Server.MaxResults)
	registerAdapters(svc, *cfg.Server.SkipVerify)

	nodeID := resolveNodeID(cfg.Server.Node)
	masterClient, err := setupMasterClient(cfg.Server.Master, nodeID, cfg.Server.MasterTLS, log)
	if err != nil {
		log.Fatal("failed to connect to master", zap.Error(err))
	}
	if masterClient != nil {
		defer masterClient.Close()
	}

	sched := setupScheduler(svc, masterClient, cfg.Checks, *cfg.Scheduler.Enabled, log)

	if cfg.Server.TLS.Enabled() && cfg.Server.TLS.ClientCAFile == "" {
		log.Warn("HTTP API: mTLS not configured (client_ca_file is empty)")
	}

	var initialPassDone sync.WaitGroup
	initialPassDone.Add(1)
	go func() {
		defer initialPassDone.Done()
		runInitialPass(svc, cfg, masterClient, log)
	}()

	srv, err := setupAPI(svc, cfg.Checks, cfg.Server, log)
	if err != nil {
		log.Fatal("failed to create API server", zap.Error(err))
	}

	gracefulShutdown(log, sched, srv, &initialPassDone)
	log.Info("stopped")
}

func logStartInfo(log *zap.Logger, cfg *config.Config) {
	log.Info("ncapd-checker starting",
		zap.String("config", flag.Lookup("config").Value.String()),
		zap.Int("checks", len(cfg.Checks)),
	)
}

func buildLogger(level string) *zap.Logger {
	lvl := zapcore.InfoLevel
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		fmt.Fprintf(os.Stderr, "warning: invalid log level %q, using info\n", level)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	log, err := cfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: failed to build logger: %v\n", err)
		os.Exit(1)
	}
	return log
}

func registerAdapters(svc *core.Service, skipVerify bool) {
	na := net.New()
	tlsa := tls.New()
	httpa := http.NewDefault(skipVerify)

	svc.Register(core.TypePortBlock, metrics.NewDecorator(na))
	svc.Register(core.TypeIPBlock, metrics.NewDecorator(na))
	svc.Register(core.TypeDNSFilter, metrics.NewDecorator(na))
	svc.Register(core.TypeRSTInject, metrics.NewDecorator(na))
	svc.Register(core.TypeSNIInspect, metrics.NewDecorator(tlsa))
	svc.Register(core.TypeTLSFP, metrics.NewDecorator(tlsa))
	svc.Register(core.TypeProtocolDetect, metrics.NewDecorator(httpa))
	svc.Register(core.TypeThrottle, metrics.NewDecorator(httpa))
	svc.Register(core.TypeActiveProbe, metrics.NewDecorator(httpa))
}

func setupMasterClient(addr, nodeID string, masterTLSCfg config.MasterTLS, log *zap.Logger) (*master.Client, error) {
	if addr == "" {
		return nil, nil
	}

	tlsCfg := &master.TLSConfig{
		Enabled:            masterTLSCfg.Enabled,
		InsecureSkipVerify: masterTLSCfg.InsecureSkipVerify,
		CAFile:             masterTLSCfg.CAFile,
		CertFile:           masterTLSCfg.CertFile,
		KeyFile:            masterTLSCfg.KeyFile,
	}

	client, err := master.New(context.Background(), addr, nodeID, tlsCfg, log)
	if err != nil {
		return nil, fmt.Errorf("grpc: connect to %s: %w", addr, err)
	}
	log.Info("connected to master for result submission", zap.String("master", addr))
	return client, nil
}

func setupScheduler(svc *core.Service, masterClient *master.Client, checks []config.Check, enabled bool, log *zap.Logger) *scheduler.Scheduler {
	sched := scheduler.New(svc, masterClient, log)

	for _, ch := range checks {
		if err := sched.Register(ch); err != nil {
			log.Error("scheduler: failed to register check, skipping",
				zap.String("id", ch.ID),
				zap.Error(err),
			)
			continue
		}
	}

	if enabled {
		sched.Start()
		log.Info("scheduler started")
	}
	return sched
}

func runInitialPass(svc *core.Service, cfg *config.Config, masterClient *master.Client, log *zap.Logger) {
	log.Info("running initial probe pass")

	for _, ch := range cfg.Checks {
		req := ch.ToReq()
		result := svc.Run(context.Background(), req)
		log.Debug("initial probe",
			zap.String("id", req.ID),
			zap.String("status", string(result.Status)),
		)
	}
	log.Info("initial probe pass complete")

	if masterClient != nil {
		if err := masterClient.SubmitBatch(context.Background(), svc.AllResults()); err != nil {
			log.Error("initial probe batch submission failed", zap.Error(err))
		}
	}
}

func resolveNodeID(cfgNodeID string) string {
	if cfgNodeID != "" {
		return cfgNodeID
	}
	return os.Getenv("NCAPD_NODE_ID")
}

func setupAPI(svc *core.Service, checks []config.Check, serverCfg config.Server, log *zap.Logger) (*api.Server, error) {
	srv, err := api.New(svc, checks, serverCfg, log)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.Start(); err != nil {
			log.Error("API server stopped", zap.Error(err))
		}
	}()
	return srv, nil
}

func gracefulShutdown(log *zap.Logger, sched *scheduler.Scheduler, srv *api.Server, initialPassDone *sync.WaitGroup) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("API server shutdown error", zap.Error(err))
	}

	schedCtx := sched.Shutdown()
	select {
	case <-schedCtx.Done():
	case <-time.After(15 * time.Second):
		log.Warn("scheduler shutdown timed out")
	}

	initialPassDone.Wait()
}
