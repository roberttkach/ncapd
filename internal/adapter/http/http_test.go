package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

func TestMain(m *testing.M) {
	os.Setenv("NCAPD_SKIP_SSRF", "1")
	os.Exit(m.Run())
}

func TestAdapter_New(t *testing.T) {
	a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if a == nil {
		t.Fatal("expected non-nil adapter")
	}
	if a.client == nil {
		t.Fatal("expected non-nil http.Client")
	}
}

func TestAdapter_Check_UnsupportedType(t *testing.T) {
	a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	result := a.Check(context.Background(), core.Request{
		ID:   "unsupported",
		Type: core.Type("unknown_type"),
	})

	if result.Status != core.Error {
		t.Errorf("status = %s, want Error for unsupported type", result.Status)
	}
}

func TestAdapter_VerifyTLS_RejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := New(&tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12})
	addr := srv.Listener.Addr().(*net.TCPAddr)
	result := a.Check(context.Background(), core.Request{
		ID:   "verify-fail",
		Type: core.TypeProtocolDetect,
		Target: core.Target{
			Host:  addr.IP.String(),
			Port:  addr.Port,
			Proto: "https",
		},
		Timeout: 10 * time.Second,
	})

	if result.Status != core.Blocked && result.Status != core.Error {
		t.Errorf("status = %s, want blocked or error", result.Status)
	}
}

func TestAdapter_CheckProtocol(t *testing.T) {
	t.Run("both plain and gRPC succeed → OK", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "proto-ok",
			Type: core.TypeProtocolDetect,
			Target: core.Target{
				Host:  addr.IP.String(),
				Port:  addr.Port,
				Proto: "https",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("status = %s, want OK: %s", result.Status, result.Detail)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "proto-timeout",
			Type: core.TypeProtocolDetect,
			Target: core.Target{
				Host:  "198.51.100.1",
				Port:  443,
				Proto: "https",
			},
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("status = %s, want Timeout", result.Status)
		}
	})

	t.Run("plain HTTPS ok, gRPC blocked → DPI detected", func(t *testing.T) {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "grpc.health.v1") {
				hj, ok := w.(http.Hijacker)
				if ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
				}
				return
			}
			w.WriteHeader(http.StatusOK)
		})

		srv := httptest.NewTLSServer(handler)
		defer srv.Close()

		addr := srv.Listener.Addr().(*net.TCPAddr)
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "proto-dpi",
			Type: core.TypeProtocolDetect,
			Target: core.Target{
				Host:  addr.IP.String(),
				Port:  addr.Port,
				Proto: "https",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("status = %s, want Blocked (DPI detected): %s", result.Status, result.Detail)
		}
		if !strings.Contains(result.Detail, "DPI suspected") {
			t.Errorf("detail = %q, want DPI mention", result.Detail)
		}
	})
}

func TestAdapter_CheckThrottle(t *testing.T) {
	t.Run("fast response → OK", func(t *testing.T) {
		data := strings.Repeat("A", 1024)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(data))
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "throttle-ok",
			Type: core.TypeThrottle,
			Target: core.Target{
				Host:          srv.Listener.Addr().(*net.TCPAddr).IP.String(),
				Port:          srv.Listener.Addr().(*net.TCPAddr).Port,
				Proto:         "https",
				ThrottleBytes: 1024,
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("status = %s, want OK", result.Status)
		}
		if result.Throughput <= 0 {
			t.Error("expected positive throughput")
		}
	})

	t.Run("timeout", func(t *testing.T) {
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "throttle-timeout",
			Type: core.TypeThrottle,
			Target: core.Target{
				Host:          "198.51.100.1",
				Port:          443,
				Proto:         "https",
				ThrottleBytes: 1024,
			},
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("status = %s, want Timeout", result.Status)
		}
	})
}

func TestAdapter_CheckActiveProbing(t *testing.T) {
	t.Run("valid HTML response → OK", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Hello</body></html>"))
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "active-ok",
			Type: core.TypeActiveProbe,
			Target: core.Target{
				Host:        srv.Listener.Addr().(*net.TCPAddr).IP.String(),
				Port:        srv.Listener.Addr().(*net.TCPAddr).Port,
				FallbackURL: srv.URL + "/",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("status = %s, want OK", result.Status)
		}
	})

	t.Run("non-HTML response → Blocked", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "ok"}`))
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "active-blocked",
			Type: core.TypeActiveProbe,
			Target: core.Target{
				Host:        srv.Listener.Addr().(*net.TCPAddr).IP.String(),
				Port:        srv.Listener.Addr().(*net.TCPAddr).Port,
				FallbackURL: srv.URL + "/",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("status = %s, want Blocked", result.Status)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "active-timeout",
			Type: core.TypeActiveProbe,
			Target: core.Target{
				Host: "198.51.100.1",
				Port: 443,
			},
			Timeout: 50 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("status = %s, want Timeout", result.Status)
		}
	})

	t.Run("invalid URL → error", func(t *testing.T) {
		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		result := a.Check(context.Background(), core.Request{
			ID:   "active-bad-url",
			Type: core.TypeActiveProbe,
			Target: core.Target{
				Host:        "example.com",
				Port:        443,
				FallbackURL: "://not-a-valid-url",
			},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Error {
			t.Errorf("status = %s, want Error", result.Status)
		}
	})
}

func TestProbeEndpoint(t *testing.T) {
	t.Run("200 response → OK", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		status, code, err := a.probeEndpoint(context.Background(), srv.URL+"/test", nil)

		if status != core.OK {
			t.Errorf("status = %s, want OK", status)
		}
		if code != 200 {
			t.Errorf("code = %d, want 200", code)
		}
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("500 response → Error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		status, code, err := a.probeEndpoint(context.Background(), srv.URL+"/test", nil)

		if status != core.Error {
			t.Errorf("status = %s, want Error", status)
		}
		if code != 500 {
			t.Errorf("code = %d, want 500", code)
		}
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("custom headers are sent", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua := r.Header.Get("User-Agent")
			if ua != "test-agent" {
				t.Errorf("User-Agent = %q, want 'test-agent'", ua)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		a := New(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		status, _, err := a.probeEndpoint(context.Background(), srv.URL+"/test", map[string]string{
			"User-Agent": "test-agent",
		})

		if status != core.OK {
			t.Errorf("status = %s, want OK", status)
		}
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})
}

func TestNewResultWithThroughput(t *testing.T) {
	result := newResultWithThroughput(core.OK, 100*time.Millisecond, "detail", "", 1024.5)

	if result.Status != core.OK {
		t.Errorf("status = %s, want OK", result.Status)
	}
	if result.Throughput != 1024.5 {
		t.Errorf("throughput = %f, want 1024.5", result.Throughput)
	}
	if result.Detail != "detail" {
		t.Errorf("detail = %q, want 'detail'", result.Detail)
	}
}

func TestIsEOF(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"EOF", fmt.Errorf("EOF"), true},
		{"unexpected EOF", fmt.Errorf("unexpected EOF"), true},
		{"other error", fmt.Errorf("connection reset"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isEOF(tt.err)
			if got != tt.want {
				t.Errorf("isEOF() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrStr(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil error", nil, ""},
		{"some error", fmt.Errorf("something went wrong"), "something went wrong"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errStr(tt.err)
			if got != tt.want {
				t.Errorf("errStr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTrunc(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncate", "hello world", 5, "hello"},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trunc(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("trunc(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}
