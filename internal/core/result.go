package core

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"time"
)

func NewResult(status Status, latency time.Duration, detail, errText string) Result {
	return Result{
		Status:  status,
		Latency: latency,
		Detail:  detail,
		Err:     errText,
	}
}

func NewTimeoutResult(latency time.Duration) Result {
	return Result{
		Status:  Timeout,
		Latency: latency,
		Err:     ErrTimeout.Error(),
	}
}

func NewErrorResult(errText string) Result {
	return Result{
		Status: Error,
		Err:    errText,
	}
}

// Timeouts map to Timeout; RST resets map to Blocked with ErrRSTReceived; all others map to Blocked.
func NewNetworkErrorResult(err error, latency time.Duration) Result {
	if IsTimeout(err) {
		return NewTimeoutResult(latency)
	}
	if IsRST(err) {
		return Result{
			Status:  Blocked,
			Latency: latency,
			Detail:  err.Error(),
			Err:     ErrRSTReceived.Error(),
		}
	}
	return Result{
		Status:  Blocked,
		Latency: latency,
		Detail:  err.Error(),
	}
}

// Uses os.IsTimeout() as the primary check, falling back to string matching
// for errors that don't implement the Timeout() interface.
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	if os.IsTimeout(err) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "deadline exceeded") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "context deadline") ||
		strings.Contains(s, "Client.Timeout")
}

// Uses errors.Is with syscall.ECONNRESET as the primary check, falling back to
// string matching for wrapped errors that don't expose the syscall directly.
func IsRST(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset by peer")
}

func IsRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection refused")
}
