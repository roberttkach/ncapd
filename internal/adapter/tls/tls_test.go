package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

func TestAdapter_New(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}
}

func TestAdapter_Check_UnsupportedType(t *testing.T) {
	a := New()
	result := a.Check(context.Background(), core.Request{
		ID:   "unsupported",
		Type: core.Type("unknown_type"),
	})

	if result.Status != core.Error {
		t.Errorf("expected status Error for unsupported type, got %s", result.Status)
	}
}

func TestAdapter_CheckSNI(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		a := New()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "sni-timeout",
			Type: core.TypeSNIInspect,
			Target: core.Target{
				Host: "198.51.100.1",
				Port: 443,
				SNI:  "example.com",
			},
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("expected status Timeout, got %s", result.Status)
		}
	})

	t.Run("connection refused → blocked via network error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "sni-refused",
			Type: core.TypeSNIInspect,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
				SNI:  "example.com",
			},
			Timeout: 5 * time.Second,
		})

		if result.Status == core.OK {
			t.Error("expected non-OK status for refused connection")
		}
	})

	t.Run("successful TLS handshake → OK", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "sni-ok",
			Type: core.TypeSNIInspect,
			Target: core.Target{
				Host: addr.IP.String(),
				Port: addr.Port,
				SNI:  addr.IP.String(),
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Error {
			t.Errorf("expected status Error for self-signed cert in SNI mode, got %s", result.Status)
		}
	})

	t.Run("self-signed cert → Error in SNI mode", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "sni-cert-error",
			Type: core.TypeSNIInspect,
			Target: core.Target{
				Host: addr.IP.String(),
				Port: addr.Port,
				SNI:  "localhost",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Error {
			t.Errorf("expected status Error in SNI mode with self-signed cert, got %s", result.Status)
		}
	})
}

func TestAdapter_CheckFingerprint(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		a := New()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "fp-timeout",
			Type: core.TypeTLSFP,
			Target: core.Target{
				Host: "198.51.100.1",
				Port: 443,
				SNI:  "example.com",
			},
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("expected status Timeout, got %s", result.Status)
		}
	})

	t.Run("connection refused → blocked via network error", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "fp-refused",
			Type: core.TypeTLSFP,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
				SNI:  "example.com",
			},
			Timeout: 5 * time.Second,
		})

		if result.Status == core.OK {
			t.Error("expected non-OK status for refused connection")
		}
	})

	t.Run("successful TLS handshake → OK (fingerprint mode)", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "fp-ok",
			Type: core.TypeTLSFP,
			Target: core.Target{
				Host: addr.IP.String(),
				Port: addr.Port,
				SNI:  "localhost",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("expected status OK, got %s: %s", result.Status, result.Err)
		}
		if result.Detail == "" {
			t.Error("expected non-empty detail with fingerprint info")
		}
	})
}

func TestHandleHandshakeError(t *testing.T) {
	t.Run("timeout → Timeout", func(t *testing.T) {
		err := fmt.Errorf("dial tcp 10.0.0.1:443: i/o timeout")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", false)

		if result.Status != core.Timeout {
			t.Errorf("expected status Timeout, got %s", result.Status)
		}
	})

	t.Run("RST → Blocked", func(t *testing.T) {
		err := fmt.Errorf("read tcp: connection reset by peer")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", false)

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked, got %s", result.Status)
		}
	})

	t.Run("TLS alert → Blocked", func(t *testing.T) {
		err := fmt.Errorf("remote error: tls: handshake failure")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", false)

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked, got %s", result.Status)
		}
	})

	t.Run("cert error in SNI mode → Error", func(t *testing.T) {
		err := fmt.Errorf("x509: certificate has expired")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", false)

		if result.Status != core.Error {
			t.Errorf("expected status Error, got %s", result.Status)
		}
	})

	t.Run("cert error in fingerprint mode → OK", func(t *testing.T) {
		err := fmt.Errorf("x509: certificate has expired")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", true)

		if result.Status != core.OK {
			t.Errorf("expected status OK in fingerprint mode, got %s", result.Status)
		}
	})

	t.Run("unknown error → Error", func(t *testing.T) {
		err := fmt.Errorf("some unknown error")
		result := handleHandshakeError(err, 100*time.Millisecond, "example.com", false)

		if result.Status != core.Error {
			t.Errorf("expected status Error, got %s", result.Status)
		}
	})
}

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS10, "TLS1.0"},
		{tls.VersionTLS11, "TLS1.1"},
		{tls.VersionTLS12, "TLS1.2"},
		{tls.VersionTLS13, "TLS1.3"},
		{0x9999, "0x9999"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tlsVersionString(tt.version)
			if got != tt.want {
				t.Errorf("tlsVersionString(0x%04x) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestIsTLSAlert(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"tls handshake failure", fmt.Errorf("remote error: tls: handshake failure"), true},
		{"unrecognized name", fmt.Errorf("tls: unrecognized name"), true},
		{"alert protocol version", fmt.Errorf("tls: alert protocol version"), true},
		{"handshake failure", fmt.Errorf("local error: handshake failure"), true},
		{"cert expired", fmt.Errorf("x509: certificate has expired"), false},
		{"connection reset", fmt.Errorf("connection reset by peer"), false},
		{"generic error", fmt.Errorf("some error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSAlert(tt.err)
			if got != tt.want {
				t.Errorf("isTLSAlert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCertErr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"x509 error", fmt.Errorf("x509: certificate has expired"), true},
		{"certificate error", fmt.Errorf("certificate validation failed"), true},
		{"other error", fmt.Errorf("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCertErr(tt.err)
			if got != tt.want {
				t.Errorf("isCertErr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDialTCP(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		_, err = dialTCP(context.Background(), fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			t.Error("expected error for refused connection")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		_, err := dialTCP(ctx, "198.51.100.1:443")
		if err == nil {
			t.Error("expected error for timeout")
		}
	})
}
