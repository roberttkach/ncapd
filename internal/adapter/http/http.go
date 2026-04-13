package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

var _ core.Dispatcher = (*Adapter)(nil)

type Adapter struct {
	client *http.Client
}

func New() *Adapter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			// InsecureSkipVerify is intentional: this tool probes censorship infrastructure
			// (DPI, throttling, active probing) where certificate validity is irrelevant.
			// We care about whether a connection can be established, not cert trust.
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &Adapter{
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *Adapter) Check(ctx context.Context, req core.Request) core.Result {
	switch req.Type {
	case core.TypeProtocolDetect:
		return a.checkProtocol(ctx, req)
	case core.TypeThrottle:
		return a.checkThrottle(ctx, req)
	case core.TypeActiveProbe:
		return a.checkActiveProbing(ctx, req)
	default:
		return core.NewErrorResult(fmt.Sprintf("http adapter: unsupported check type %s", req.Type))
	}
}

func (a *Adapter) checkProtocol(ctx context.Context, req core.Request) core.Result {
	baseURL := fmt.Sprintf("%s://%s:%d", resolveProto(req), req.Target.Host, req.Target.Port)

	// Probe with generic browser UA, then with gRPC-specific headers.
	// DPI systems often block gRPC by inspecting Content-Type or TE headers
	// while allowing plain HTTPS. A mismatch indicates protocol-based filtering.
	plainStart := time.Now()
	plainStatus, plainCode, plainErr := a.probeEndpoint(ctx, baseURL, map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
	})
	plainLatency := time.Since(plainStart)

	grpcStart := time.Now()
	grpcStatus, grpcCode, grpcErr := a.probeEndpoint(ctx, baseURL+"/grpc.health.v1.Health/Check", map[string]string{
		"Content-Type": "application/grpc",
		"TE":           "trailers",
		"User-Agent":   "grpc-go/1.67.1",
	})
	grpcLatency := time.Since(grpcStart)

	if plainStatus == core.OK && grpcStatus == core.Blocked {
		return core.NewResult(core.Blocked, grpcLatency,
			fmt.Sprintf("DPI suspected: plain HTTPS %d in %s, gRPC-pattern blocked (%v)",
				plainCode, plainLatency, grpcErr),
			"",
		)
	}

	if plainStatus != core.OK {
		return core.NewResult(plainStatus, plainLatency,
			fmt.Sprintf("HTTP %d", plainCode),
			errStr(plainErr),
		)
	}

	return core.NewResult(core.OK, grpcLatency,
		fmt.Sprintf("plain=%d(%s), gRPC-pattern=%d(%s)",
			plainCode, plainLatency, grpcCode, grpcLatency),
		"",
	)
}

func (a *Adapter) checkThrottle(ctx context.Context, req core.Request) core.Result {
	url := fmt.Sprintf("%s://%s:%d/", resolveProto(req), req.Target.Host, req.Target.Port)

	limit := req.Target.ThrottleBytes
	if limit <= 0 {
		limit = 1 << 20
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.NewErrorResult(err.Error())
	}
	httpReq.Header.Set("Range", fmt.Sprintf("bytes=0-%d", limit-1))

	start := time.Now()
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return core.NewNetworkErrorResult(err, time.Since(start))
	}
	defer resp.Body.Close()

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	elapsed := time.Since(start)

	if err != nil && !isEOF(err) {
		return core.NewNetworkErrorResult(err, elapsed)
	}

	if elapsed == 0 {
		elapsed = time.Millisecond
	}
	bps := float64(n) / elapsed.Seconds()

	status := core.OK
	detail := fmt.Sprintf("downloaded %d bytes in %s → %.2f KB/s", n, elapsed, bps/1024)

	if bps < 10*1024 && n > 0 {
		status = core.Blocked
		detail += " [THROTTLED]"
	}

	return newResultWithThroughput(status, elapsed, detail, "", bps)
}

func (a *Adapter) checkActiveProbing(ctx context.Context, req core.Request) core.Result {
	url := req.Target.FallbackURL
	if url == "" {
		url = fmt.Sprintf("https://%s:%d/", req.Target.Host, req.Target.Port)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.NewErrorResult(err.Error())
	}
	httpReq.Header.Set("User-Agent", "curl/8.4.0")

	start := time.Now()
	resp, err := a.client.Do(httpReq)
	latency := time.Since(start)
	if err != nil {
		return core.NewNetworkErrorResult(err, latency)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	body := string(bodyBytes)

	looksReal := resp.StatusCode == 200 &&
		(strings.Contains(body, "<html") || strings.Contains(body, "<!DOCTYPE"))

	if !looksReal {
		return core.NewResult(core.Blocked, latency,
			fmt.Sprintf("fallback site returned HTTP %d, body[0:64]=%q — may be detectable by active probing",
				resp.StatusCode, trunc(body, 64)),
			"",
		)
	}

	return core.NewResult(core.OK, latency,
		fmt.Sprintf("fallback site OK: HTTP %d, HTML present", resp.StatusCode),
		"",
	)
}

func (a *Adapter) probeEndpoint(ctx context.Context, url string, headers map[string]string) (core.Status, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return core.Error, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		if core.IsTimeout(err) {
			return core.Timeout, 0, err
		}
		return core.Blocked, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	if resp.StatusCode >= 500 {
		return core.Error, resp.StatusCode, nil
	}
	return core.OK, resp.StatusCode, nil
}

func newResultWithThroughput(status core.Status, latency time.Duration, detail, errText string, throughput float64) core.Result {
	return core.Result{
		Status:     status,
		Latency:    latency,
		Detail:     detail,
		Err:        errText,
		Throughput: throughput,
	}
}

func isEOF(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "EOF") || strings.Contains(s, "unexpected EOF")
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func resolveProto(req core.Request) string {
	if req.Target.Proto != "" {
		return req.Target.Proto
	}
	return "https"
}
