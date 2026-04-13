package core

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Status string

const (
	OK      Status = "ok"
	Timeout Status = "timeout"
	Blocked Status = "blocked"
	Error   Status = "error"
)

type Type string

const (
	TypePortBlock      Type = "port_blocking"
	TypeIPBlock        Type = "ip_blocking"
	TypeDNSFilter      Type = "dns_filtering"
	TypeRSTInject      Type = "rst_injection"
	TypeSNIInspect     Type = "sni_inspection"
	TypeTLSFP          Type = "tls_fingerprint"
	TypeProtocolDetect Type = "protocol_detection"
	TypeThrottle       Type = "throttling"
	TypeActiveProbe    Type = "active_probing"
)

type Result struct {
	ID         string        `json:"request_id"`
	Type       Type          `json:"type"`
	Status     Status        `json:"status"`
	At         time.Time     `json:"checked_at"`
	Latency    time.Duration `json:"latency_ns"`
	Throughput float64       `json:"throughput_bps,omitempty"`
	Detail     string        `json:"detail,omitempty"`
	Err        string        `json:"error,omitempty"`
	Host       string        `json:"target_host,omitempty"`
}

type Request struct {
	ID      string
	Type    Type
	Target  Target
	Timeout time.Duration
}

type Target struct {
	Host          string `json:"host,omitempty"`
	IP            string `json:"ip,omitempty"`
	Port          int    `json:"port,omitempty"`
	Proto         string `json:"proto,omitempty"`
	SNI           string `json:"sni,omitempty"`
	FallbackURL   string `json:"fallback_url,omitempty"`
	ThrottleBytes int64  `json:"throttle_bytes,omitempty"`
}

func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
}

type Provider interface {
	Run(ctx context.Context, req Request) Result
	AllResults() []Result
	GetResult(id string) (Result, bool)
}
