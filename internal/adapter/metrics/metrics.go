package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/roberttkach/ncapd/internal/core"
)

var (
	checkTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ncapd",
			Subsystem: "check",
			Name:      "total",
			Help:      "Total number of checks executed, partitioned by check ID, type and result status.",
		},
		[]string{"check_id", "check_type", "status"},
	)

	checkDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ncapd",
			Subsystem: "check",
			Name:      "duration_seconds",
			Help:      "Latency of check execution in seconds, partitioned by check ID and type.",
			Buckets:   []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"check_id", "check_type"},
	)

	checkBlocked = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ncapd",
			Subsystem: "check",
			Name:      "blocked",
			Help:      "1 if the last execution of the check resulted in blocked/error/timeout, 0 if ok.",
		},
		[]string{"check_id", "check_type"},
	)

	checkThroughputBps = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ncapd",
			Subsystem: "check",
			Name:      "throughput_bytes_per_second",
			Help:      "Observed throughput in bytes per second for throttling checks.",
		},
		[]string{"check_id", "check_type"},
	)
)

type Decorator struct {
	inner core.Dispatcher
}

func NewDecorator(inner core.Dispatcher) *Decorator {
	return &Decorator{inner: inner}
}

func (d *Decorator) Check(ctx context.Context, req core.Request) core.Result {
	result := d.inner.Check(ctx, req)
	recordMetrics(req.ID, string(req.Type), result)
	return result
}

func Handler() http.Handler {
	return promhttp.Handler()
}

func recordMetrics(checkID, checkType string, result core.Result) {
	labels := prometheus.Labels{
		"check_id":   checkID,
		"check_type": checkType,
		"status":     string(result.Status),
	}

	checkTotal.With(labels).Inc()

	checkDurationSeconds.With(prometheus.Labels{
		"check_id":   checkID,
		"check_type": checkType,
	}).Observe(result.Latency.Seconds())

	blockedVal := 0.0
	if result.Status != core.OK {
		blockedVal = 1.0
	}
	checkBlocked.With(prometheus.Labels{
		"check_id":   checkID,
		"check_type": checkType,
	}).Set(blockedVal)

	if result.Throughput > 0 {
		checkThroughputBps.With(prometheus.Labels{
			"check_id":   checkID,
			"check_type": checkType,
		}).Set(result.Throughput)
	}
}
