package validate

import (
	"net"
	"testing"

	"github.com/roberttkach/ncapd/internal/core"
)

func TestHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{"valid hostname", "example.com", false},
		{"valid hostname with hyphen", "my-host.example.com", false},
		{"valid single label", "localhost", false},
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv6", "2001:db8::1", false},
		{"valid IPv6 loopback", "::1", false},
		{"empty host", "", true},
		{"too long label", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", true},
		{"label starts with hyphen", "-example.com", true},
		{"label ends with hyphen", "example-.com", true},
		{"invalid character", "exa@mple.com", true},
		{"spaces in hostname", "example .com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Host(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("Host(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
		})
	}
}

func TestIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv6", "2001:db8::1", false},
		{"valid loopback", "127.0.0.1", false},
		{"empty IP", "", true},
		{"invalid IP", "999.999.999.999", true},
		{"malformed", "not-an-ip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("IP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port 80", 80, false},
		{"valid port 443", 443, false},
		{"valid port 65535", 65535, false},
		{"valid port 1", 1, false},
		{"port 0", 0, true},
		{"port 65536", 65536, true},
		{"negative port", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Port(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("Port(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestTarget(t *testing.T) {
	tests := []struct {
		name      string
		target    core.Target
		checkType core.Type
		wantErr   bool
	}{
		{
			name:      "valid port_blocking",
			target:    core.Target{Host: "example.com", Port: 443},
			checkType: core.TypePortBlock,
			wantErr:   false,
		},
		{
			name:      "missing host for port_blocking",
			target:    core.Target{Port: 443},
			checkType: core.TypePortBlock,
			wantErr:   true,
		},
		{
			name:      "missing port for port_blocking",
			target:    core.Target{Host: "example.com"},
			checkType: core.TypePortBlock,
			wantErr:   true,
		},
		{
			name:      "valid ip_blocking",
			target:    core.Target{Host: "example.com", IP: "1.2.3.4"},
			checkType: core.TypeIPBlock,
			wantErr:   false,
		},
		{
			name:      "missing IP for ip_blocking",
			target:    core.Target{Host: "example.com"},
			checkType: core.TypeIPBlock,
			wantErr:   true,
		},
		{
			name:      "invalid IP for ip_blocking",
			target:    core.Target{Host: "example.com", IP: "invalid"},
			checkType: core.TypeIPBlock,
			wantErr:   true,
		},
		{
			name:      "valid dns_filtering",
			target:    core.Target{Host: "example.com"},
			checkType: core.TypeDNSFilter,
			wantErr:   false,
		},
		{
			name:      "valid rst_injection",
			target:    core.Target{Host: "example.com", Port: 80},
			checkType: core.TypeRSTInject,
			wantErr:   false,
		},
		{
			name:      "valid sni_inspection",
			target:    core.Target{Host: "example.com", Port: 443, SNI: "example.com"},
			checkType: core.TypeSNIInspect,
			wantErr:   false,
		},
		{
			name:      "valid active_probing without fallback",
			target:    core.Target{Host: "example.com", Port: 443},
			checkType: core.TypeActiveProbe,
			wantErr:   false,
		},
		{
			name:      "valid active_probing with valid fallback",
			target:    core.Target{Host: "example.com", Port: 443, FallbackURL: "https://example.com/"},
			checkType: core.TypeActiveProbe,
			wantErr:   false,
		},
		{
			name:      "invalid port for active_probing",
			target:    core.Target{Host: "example.com", Port: 99999},
			checkType: core.TypeActiveProbe,
			wantErr:   true,
		},
		{
			name:      "valid throttling",
			target:    core.Target{Host: "example.com", Port: 443},
			checkType: core.TypeThrottle,
			wantErr:   false,
		},
		{
			name:      "missing host for throttling",
			target:    core.Target{Port: 443},
			checkType: core.TypeThrottle,
			wantErr:   true,
		},
		{
			name:      "valid protocol_detection",
			target:    core.Target{Host: "example.com", Port: 443},
			checkType: core.TypeProtocolDetect,
			wantErr:   false,
		},
		{
			name:      "missing host for ip_blocking",
			target:    core.Target{IP: "1.2.3.4"},
			checkType: core.TypeIPBlock,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Target(tt.target, tt.checkType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Target() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHost_SSRFPrevention(t *testing.T) {
	blockedHosts := []string{
		"192.168.1.100", "10.0.0.5", "127.0.0.1",
		"169.254.169.254", "169.254.0.1",
		"localhost", "metadata", "::1", "fe80::1",
	}

	checkTypes := []core.Type{
		core.TypePortBlock, core.TypeRSTInject,
		core.TypeSNIInspect, core.TypeTLSFP,
		core.TypeProtocolDetect, core.TypeThrottle,
		core.TypeActiveProbe,
	}

	for _, host := range blockedHosts {
		for _, ct := range checkTypes {
			t.Run(string(ct)+"/"+host, func(t *testing.T) {
				err := Target(core.Target{Host: host, Port: 443}, ct)
				if err == nil {
					t.Errorf("host=%q should be blocked for SSRF prevention", host)
				}
			})
		}
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		blocked bool
	}{
		{"public IP", "8.8.8.8", false},
		{"cloudflare DNS", "1.1.1.1", false},
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.0.0.255", "127.0.0.255", true},
		{"private 10.x", "10.0.0.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 172.31.x", "172.31.255.255", true},
		{"public 172.32.x", "172.32.0.1", false},
		{"private 192.168.x", "192.168.1.1", true},
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 public", "2001:db8::1", false},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 unique local", "fc00::1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := IsBlockedIP(ip)
			if got != tt.blocked {
				t.Errorf("IsBlockedIP(%q) = %v, want %v", tt.ip, got, tt.blocked)
			}
		})
	}
}

func TestIsBlockedHostname(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		blocked bool
	}{
		{"localhost", "localhost", true},
		{"LOCALHOST uppercase", "LOCALHOST", true},
		{"metadata", "metadata", true},
		{"GCP metadata", "metadata.google.internal", true},
		{"example.com", "example.com", false},
		{"google.com", "google.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBlockedHostname(tt.host)
			if got != tt.blocked {
				t.Errorf("isBlockedHostname(%q) = %v, want %v", tt.host, got, tt.blocked)
			}
		})
	}
}

func TestFallbackURL(t *testing.T) {
	t.Run("empty URL is ok", func(t *testing.T) {
		err := FallbackURL("", "example.com", 443)
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("valid https URL", func(t *testing.T) {
		err := FallbackURL("https://example.com/", "example.com", 443)
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("valid http URL", func(t *testing.T) {
		err := FallbackURL("http://example.com/", "example.com", 80)
		if err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})

	t.Run("ftp scheme is rejected", func(t *testing.T) {
		err := FallbackURL("ftp://example.com/", "example.com", 21)
		if err == nil {
			t.Error("expected error for ftp scheme")
		}
	})

	t.Run("localhost is blocked", func(t *testing.T) {
		err := FallbackURL("https://localhost/", "localhost", 443)
		if err == nil {
			t.Error("expected error for localhost")
		}
	})

	t.Run("169.254.169.254 is blocked", func(t *testing.T) {
		err := FallbackURL("http://169.254.169.254/latest", "169.254.169.254", 80)
		if err == nil {
			t.Error("expected error for metadata IP")
		}
	})

	t.Run("unresolvable host returns error", func(t *testing.T) {
		err := FallbackURL("https://this-domain-definitely-does-not-exist-xyz123.invalid/", "", 443)
		if err == nil {
			t.Error("expected error for unresolvable host")
		}
	})
}
