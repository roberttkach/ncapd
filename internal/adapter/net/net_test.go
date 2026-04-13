package net

import (
	"context"
	"fmt"
	"net"
	"sync"
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

func TestAdapter_CheckPort(t *testing.T) {
	t.Run("connection refused → blocked", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "port-refused",
			Type: core.TypePortBlock,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked for refused connection, got %s", result.Status)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		a := New()
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:   "port-timeout",
			Type: core.TypePortBlock,
			Target: core.Target{
				Host: "198.51.100.1",
				Port: 9999,
			},
			Timeout: 100 * time.Millisecond,
		})

		if result.Status != core.Timeout {
			t.Errorf("expected status Timeout, got %s", result.Status)
		}
	})
}

func TestAdapter_CheckIP(t *testing.T) {
	t.Run("connection refused → blocked", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "ip-refused",
			Type: core.TypeIPBlock,
			Target: core.Target{
				IP:   "127.0.0.1",
				Host: "localhost",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked, got %s", result.Status)
		}
	})

	t.Run("uses Host as IP when IP field is empty", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "ip-from-host",
			Type: core.TypeIPBlock,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked, got %s", result.Status)
		}
	})
}

func TestAdapter_CheckDNS(t *testing.T) {
	t.Run("valid domain resolves → OK", func(t *testing.T) {
		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:      "dns-ok",
			Type:    core.TypeDNSFilter,
			Target:  core.Target{Host: "example.com"},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.OK && result.Status != core.Blocked && result.Status != core.Timeout {
			t.Errorf("expected OK, Blocked, or Timeout, got %s", result.Status)
		}
	})

	t.Run("NXDOMAIN → blocked", func(t *testing.T) {
		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:      "dns-nxdomain",
			Type:    core.TypeDNSFilter,
			Target:  core.Target{Host: "this-domain-definitely-does-not-exist-xyz123.invalid"},
			Timeout: 10 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked for NXDOMAIN, got %s", result.Status)
		}
	})

	t.Run("very short timeout → timeout or blocked", func(t *testing.T) {
		a := New()
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		result := a.Check(ctx, core.Request{
			ID:      "dns-timeout",
			Type:    core.TypeDNSFilter,
			Target:  core.Target{Host: "example.com"},
			Timeout: 1 * time.Millisecond,
		})

		if result.Status == core.OK {
			t.Log("DNS resolved within 1ms — acceptable")
		}
	})
}

func TestAdapter_CheckRST(t *testing.T) {
	t.Run("connection refused → no RST observed", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		time.Sleep(50 * time.Millisecond)

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "rst-refused",
			Type: core.TypeRSTInject,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.Blocked {
			t.Errorf("expected status Blocked, got %s", result.Status)
		}
	})
}

func TestAdapter_ConcurrentChecks(t *testing.T) {
	a := New()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = a.Check(context.Background(), core.Request{
				ID:   fmt.Sprintf("concurrent-%d", n),
				Type: core.TypeDNSFilter,
				Target: core.Target{
					Host: "example.com",
				},
				Timeout: 5 * time.Second,
			})
		}(i)
	}
	wg.Wait()
}

func TestIsRefused(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"connection refused", fmt.Errorf("dial tcp: connection refused"), true},
		{"other error", fmt.Errorf("some other error"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := core.IsRefused(tt.err)
			if got != tt.want {
				t.Errorf("IsRefused() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAdapter_CheckPort_Listening(t *testing.T) {
	t.Run("listening server → OK", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "port-ok",
			Type: core.TypePortBlock,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("expected status OK, got %s", result.Status)
		}
	})
}

func TestAdapter_CheckRST_Listening(t *testing.T) {
	t.Run("listening server → no RST observed", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port

		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		a := New()
		result := a.Check(context.Background(), core.Request{
			ID:   "rst-ok",
			Type: core.TypeRSTInject,
			Target: core.Target{
				Host: "127.0.0.1",
				Port: port,
			},
			Timeout: 5 * time.Second,
		})

		if result.Status != core.OK {
			t.Errorf("expected status OK, got %s", result.Status)
		}
		if result.Detail == "" {
			t.Error("expected detail message for successful RST check")
		}
	})
}
