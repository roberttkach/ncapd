package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

var _ core.Dispatcher = (*Adapter)(nil)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Check(ctx context.Context, req core.Request) core.Result {
	switch req.Type {
	case core.TypeSNIInspect:
		return a.checkSNI(ctx, req)
	case core.TypeTLSFP:
		return a.checkFingerprint(ctx, req)
	default:
		return core.NewErrorResult(fmt.Sprintf("tls adapter: unsupported check type %s", req.Type))
	}
}

func (a *Adapter) checkSNI(ctx context.Context, req core.Request) core.Result {
	sni := resolveSNI(req)

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	state, res, ok := dialTLS(ctx, req, sni, tlsCfg)
	if !ok {
		return res
	}

	return core.NewResult(core.OK, state.latency,
		fmt.Sprintf("TLS %s cipher=0x%04x sni=%s",
			tlsVersionString(state.version), state.cipher, sni),
		"",
	)
}

func (a *Adapter) checkFingerprint(ctx context.Context, req core.Request) core.Result {
	sni := resolveSNI(req)

	tlsCfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}

	state, res, ok := dialTLS(ctx, req, sni, tlsCfg)
	if !ok {
		return res
	}

	return core.NewResult(core.OK, state.latency,
		fmt.Sprintf("TLS fingerprint OK (stdlib Chrome-like) TLS=%s cipher=0x%04x",
			tlsVersionString(state.version), state.cipher),
		"",
	)
}

func handleHandshakeError(err error, latency time.Duration, sni string, isFingerprintMode bool) core.Result {
	if core.IsTimeout(err) {
		return core.NewTimeoutResult(latency)
	}
	if core.IsRST(err) || isTLSAlert(err) {
		return core.NewResult(core.Blocked, latency,
			fmt.Sprintf("SNI=%s", sni),
			core.ErrSNIRejected.Error(),
		)
	}
	if isFingerprintMode && isCertErr(err) {
		return core.NewResult(core.OK, latency,
			fmt.Sprintf("handshake OK (cert issue: %v)", err),
			"",
		)
	}
	if isCertErr(err) {
		return core.NewResult(core.Error, latency,
			fmt.Sprintf("certificate validation failed: %v", err),
			"",
		)
	}
	return core.NewErrorResult(err.Error())
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func isTLSAlert(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "alert") ||
		strings.Contains(s, "handshake failure") ||
		strings.Contains(s, "unrecognized name") ||
		strings.Contains(s, "bad certificate") ||
		strings.Contains(s, "protocol version")
}

func isCertErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "certificate") || strings.Contains(s, "x509")
}

func dialTLS(ctx context.Context, req core.Request, sni string, tlsCfg *tls.Config) (state tlsState, res core.Result, ok bool) {
	addr := req.Target.Addr()

	start := time.Now()
	rawConn, err := dialTCP(ctx, addr)
	if err != nil {
		return tlsState{}, core.NewNetworkErrorResult(err, time.Since(start)), false
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tlsCfg)

	if err = tlsConn.HandshakeContext(ctx); err != nil {
		latency := time.Since(start)
		_ = tlsConn.Close()
		return tlsState{}, handleHandshakeError(err, latency, sni, tlsCfg.InsecureSkipVerify), false
	}

	s := tlsConn.ConnectionState()
	_ = tlsConn.Close()
	return tlsState{
		version: s.Version,
		cipher:  s.CipherSuite,
		latency: time.Since(start),
	}, core.Result{}, true
}

type tlsState struct {
	version uint16
	cipher  uint16
	latency time.Duration
}

func resolveSNI(req core.Request) string {
	if req.Target.SNI != "" {
		return req.Target.SNI
	}
	return req.Target.Host
}
