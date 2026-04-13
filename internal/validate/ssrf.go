package validate

import (
	"fmt"
	"net"
	"os"
	"strings"
)

var blockedIPNets = []*net.IPNet{
	mustParseCIDR("127.0.0.0/8"),
	mustParseCIDR("10.0.0.0/8"),
	mustParseCIDR("172.16.0.0/12"),
	mustParseCIDR("192.168.0.0/16"),
	mustParseCIDR("169.254.0.0/16"),
	mustParseCIDR("::1/128"),
	mustParseCIDR("fc00::/7"),
	mustParseCIDR("fe80::/10"),
}

var blockedHostnames = map[string]bool{
	"localhost":                true,
	"localhost.local":          true,
	"metadata":                 true,
	"metadata.google.internal": true,
}

// Cloud metadata IP: explicitly blocked even within link-local range.
var cloudMetadataIP = net.ParseIP("169.254.169.254")

func IsBlockedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.Equal(cloudMetadataIP) {
		return true
	}
	for _, cidr := range blockedIPNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isBlockedHostname(host string) bool {
	return blockedHostnames[strings.ToLower(host)]
}

func mustParseCIDR(cidr string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic("validate: invalid CIDR in blocklist: " + cidr)
	}
	return ipNet
}

func CheckRuntime(host string) error {
	if os.Getenv("NCAPD_SKIP_SSRF") == "1" {
		return nil
	}
	if host == "" {
		return fmt.Errorf("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("host %q resolves to blocked IP", host)
		}
		return nil
	}
	if isBlockedHostname(host) {
		return fmt.Errorf("hostname %q is blocked", host)
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if IsBlockedIP(ip) {
			return fmt.Errorf("host %q resolves to blocked IP %s", host, addr)
		}
	}
	return nil
}
