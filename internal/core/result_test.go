package core

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestNewResult(t *testing.T) {
	r := NewResult(OK, 5*time.Millisecond, "connected", "")

	if r.Status != OK {
		t.Errorf("status = %s, want %s", r.Status, OK)
	}
	if r.Latency != 5*time.Millisecond {
		t.Errorf("latency = %v, want 5ms", r.Latency)
	}
	if r.Detail != "connected" {
		t.Errorf("detail = %q, want %q", r.Detail, "connected")
	}
	if r.Err != "" {
		t.Errorf("err = %q, want empty", r.Err)
	}
}

func TestNewTimeoutResult(t *testing.T) {
	r := NewTimeoutResult(100 * time.Millisecond)

	if r.Status != Timeout {
		t.Errorf("status = %s, want %s", r.Status, Timeout)
	}
	if r.Latency != 100*time.Millisecond {
		t.Errorf("latency = %v, want 100ms", r.Latency)
	}
	if r.Err != ErrTimeout.Error() {
		t.Errorf("err = %q, want %q", r.Err, ErrTimeout.Error())
	}
}

func TestNewErrorResult(t *testing.T) {
	r := NewErrorResult("custom error text")

	if r.Status != Error {
		t.Errorf("status = %s, want %s", r.Status, Error)
	}
	if r.Err != "custom error text" {
		t.Errorf("err = %q, want %q", r.Err, "custom error text")
	}
}

func TestNewNetworkErrorResult(t *testing.T) {
	t.Run("timeout error maps to Timeout", func(t *testing.T) {
		err := &net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}
		r := NewNetworkErrorResult(err, 50*time.Millisecond)

		if r.Status != Timeout {
			t.Errorf("status = %s, want %s", r.Status, Timeout)
		}
		if r.Err != ErrTimeout.Error() {
			t.Errorf("err = %q, want %q", r.Err, ErrTimeout.Error())
		}
	})

	t.Run("RST error maps to Blocked with ErrRSTReceived", func(t *testing.T) {
		err := &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{
				Syscall: "connect",
				Err:     syscall.ECONNRESET,
			},
		}
		r := NewNetworkErrorResult(err, 30*time.Millisecond)

		if r.Status != Blocked {
			t.Errorf("status = %s, want %s", r.Status, Blocked)
		}
		if r.Err != ErrRSTReceived.Error() {
			t.Errorf("err = %q, want %q", r.Err, ErrRSTReceived.Error())
		}
	})

	t.Run("generic network error maps to Blocked", func(t *testing.T) {
		err := fmt.Errorf("network unreachable")
		r := NewNetworkErrorResult(err, 10*time.Millisecond)

		if r.Status != Blocked {
			t.Errorf("status = %s, want %s", r.Status, Blocked)
		}
		if r.Detail != "network unreachable" {
			t.Errorf("detail = %q, want %q", r.Detail, "network unreachable")
		}
	})
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"os.ErrDeadlineExceeded", os.ErrDeadlineExceeded, true},
		{"os.ErrDeadlineExceeded wrapped", fmt.Errorf("wrap: %w", os.ErrDeadlineExceeded), true},
		{"string: deadline exceeded", errors.New("deadline exceeded"), true},
		{"string: i/o timeout", errors.New("i/o timeout"), true},
		{"string: context deadline", errors.New("context deadline exceeded"), true},
		{"string: Client.Timeout", errors.New("Get: Client.Timeout exceeded"), true},
		{"generic error", errors.New("some error"), false},
		{"connection refused", errors.New("connection refused"), false},
		{"ECONNRESET", syscall.ECONNRESET, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTimeout(tt.err); got != tt.want {
				t.Errorf("IsTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRST(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"syscall.ECONNRESET directly", syscall.ECONNRESET, true},
		{"*net.OpError with ECONNRESET", &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNRESET},
		}, true},
		{"wrapped ECONNRESET", fmt.Errorf("dial: %w", &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNRESET},
		}), true},
		{"string: connection reset by peer", errors.New("read tcp: connection reset by peer"), true},
		{"generic error", errors.New("some error"), false},
		{"connection refused", errors.New("connection refused"), false},
		{"timeout error", os.ErrDeadlineExceeded, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRST(tt.err); got != tt.want {
				t.Errorf("IsRST() = %v, want %v", got, tt.want)
			}
		})
	}
}
