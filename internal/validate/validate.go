package validate

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/roberttkach/ncapd/internal/core"
)

var (
	ErrHostRequired       = errors.New("host is required")
	ErrHostInvalid        = errors.New("host is invalid")
	ErrIPRequired         = errors.New("ip is required")
	ErrIPInvalid          = errors.New("ip is invalid")
	ErrPortRequired       = errors.New("port is required")
	ErrPortOutOfRange     = errors.New("port is out of range (1-65535)")
	ErrFallbackURLInvalid = errors.New("fallback_url is invalid")
	ErrFallbackURLBlocked = errors.New("fallback_url resolves to a blocked address")
)

func Target(t core.Target, checkType core.Type) error {
	switch checkType {
	case core.TypePortBlock, core.TypeSNIInspect, core.TypeTLSFP, core.TypeProtocolDetect, core.TypeThrottle:
		if err := requireHostAndPort(t, checkType); err != nil {
			return err
		}

	case core.TypeIPBlock:
		if t.IP == "" {
			return fmt.Errorf("%w for check type %s", ErrIPRequired, checkType)
		}
		if err := IP(t.IP); err != nil {
			return fmt.Errorf("ip: %w", err)
		}
		// TypeIPBlock requires host but NOT port
		if t.Host == "" {
			return fmt.Errorf("%w for check type %s", ErrHostRequired, checkType)
		}
		if err := Host(t.Host); err != nil {
			return fmt.Errorf("host: %w", err)
		}

	case core.TypeDNSFilter:
		if t.Host == "" {
			return fmt.Errorf("%w for check type %s", ErrHostRequired, checkType)
		}
		if err := Host(t.Host); err != nil {
			return fmt.Errorf("host: %w", err)
		}

	case core.TypeRSTInject:
		if err := requireHostAndPort(t, checkType); err != nil {
			return err
		}

	case core.TypeActiveProbe:
		if t.FallbackURL != "" {
			if err := FallbackURL(t.FallbackURL, t.Host, t.Port); err != nil {
				return fmt.Errorf("fallback_url: %w", err)
			}
		}
		if err := requireHostAndPort(t, checkType); err != nil {
			return err
		}

	default:
		// Unknown check type: perform minimal validation
		if t.Host != "" {
			if err := Host(t.Host); err != nil {
				return fmt.Errorf("host: %w", err)
			}
		}
		if t.IP != "" {
			if err := IP(t.IP); err != nil {
				return fmt.Errorf("ip: %w", err)
			}
		}
		if t.Port != 0 {
			if err := Port(t.Port); err != nil {
				return fmt.Errorf("port: %w", err)
			}
		}
		if t.FallbackURL != "" {
			if err := FallbackURL(t.FallbackURL, t.Host, t.Port); err != nil {
				return fmt.Errorf("fallback_url: %w", err)
			}
		}
	}

	return nil
}

func Host(host string) error {
	if host == "" {
		return ErrHostRequired
	}

	if ip := net.ParseIP(host); ip != nil {
		return nil
	}

	if isValidHostname(host) {
		return nil
	}

	return fmt.Errorf("%w: %q", ErrHostInvalid, host)
}

func IP(ip string) error {
	if ip == "" {
		return ErrIPRequired
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %q", ErrIPInvalid, ip)
	}
	return nil
}

func Port(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: %d", ErrPortOutOfRange, port)
	}
	return nil
}

func FallbackURL(rawURL, defaultHost string, defaultPort int) error {
	if rawURL == "" {
		return nil
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFallbackURLInvalid, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q not allowed, only http/https", ErrFallbackURLInvalid, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		host = defaultHost
	}

	if host == "" {
		return fmt.Errorf("%w: no host specified", ErrFallbackURLInvalid)
	}

	if isBlockedHostname(host) {
		return fmt.Errorf("%w: hostname %q is blocked", ErrFallbackURLBlocked, host)
	}

	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: IP %s is blocked", ErrFallbackURLBlocked, host)
		}
		return nil
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("%w: DNS lookup failed: %w", ErrFallbackURLInvalid, err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if isBlockedIP(ip) {
			return fmt.Errorf("%w: resolves to blocked IP %s", ErrFallbackURLBlocked, addr)
		}
	}

	return nil
}

func requireHostAndPort(t core.Target, checkType core.Type) error {
	if t.Host == "" {
		return fmt.Errorf("%w for check type %s", ErrHostRequired, checkType)
	}
	if err := Host(t.Host); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	if t.Port == 0 {
		return fmt.Errorf("%w for check type %s", ErrPortRequired, checkType)
	}
	if err := Port(t.Port); err != nil {
		return fmt.Errorf("port: %w", err)
	}
	return nil
}

func isValidHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}

	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}
