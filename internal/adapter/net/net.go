package net

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
	"github.com/roberttkach/ncapd/internal/validate"
)

var _ core.Dispatcher = (*Adapter)(nil)

type Adapter struct{}

func New() *Adapter { return &Adapter{} }

func (a *Adapter) Check(ctx context.Context, req core.Request) core.Result {
	switch req.Type {
	case core.TypePortBlock:
		return a.checkPort(ctx, req)
	case core.TypeIPBlock:
		return a.checkIP(ctx, req)
	case core.TypeDNSFilter:
		return a.checkDNS(ctx, req)
	case core.TypeRSTInject:
		return a.checkRST(ctx, req)
	default:
		return core.NewErrorResult(fmt.Sprintf("net adapter: unsupported check type %s", req.Type))
	}
}

func (a *Adapter) checkPort(ctx context.Context, req core.Request) core.Result {
	if err := validate.CheckRuntime(req.Target.Host); err != nil {
		return core.NewResult(core.Blocked, 0, err.Error(), "")
	}
	return checkTCP(ctx, req.Target.Addr())
}

func (a *Adapter) checkIP(ctx context.Context, req core.Request) core.Result {
	ip := req.Target.IP
	if ip == "" {
		ip = req.Target.Host
	}
	if err := validate.CheckRuntime(ip); err != nil {
		return core.NewResult(core.Blocked, 0, err.Error(), "")
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(req.Target.Port))
	return checkTCP(ctx, addr)
}

func (a *Adapter) checkDNS(ctx context.Context, req core.Request) core.Result {
	start := time.Now()
	r := &net.Resolver{PreferGo: true}
	addrs, err := r.LookupHost(ctx, req.Target.Host)
	latency := time.Since(start)

	if err != nil {
		if core.IsTimeout(err) {
			return core.NewTimeoutResult(latency)
		}
		return core.NewResult(core.Blocked, latency, "", core.ErrDNSFiltered.Error())
	}

	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && validate.IsBlockedIP(ip) {
			return core.NewResult(core.Blocked, latency,
				fmt.Sprintf("resolved to blocked IP %s", addr), "")
		}
	}

	return core.NewResult(core.OK, latency,
		fmt.Sprintf("resolved: %s", strings.Join(addrs, ", ")), "")
}

func (a *Adapter) checkRST(ctx context.Context, req core.Request) core.Result {
	if err := validate.CheckRuntime(req.Target.Host); err != nil {
		return core.NewResult(core.Blocked, 0, err.Error(), "")
	}
	result := checkTCP(ctx, req.Target.Addr())
	if result.Status == core.OK {
		result.Detail = "no RST observed: connection established normally"
	}
	return result
}

func checkTCP(ctx context.Context, addr string) core.Result {
	start := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	latency := time.Since(start)

	if err != nil {
		if core.IsRefused(err) {
			return core.NewResult(core.Blocked, latency,
				"connection refused: port closed or filtered", "")
		}
		return core.NewNetworkErrorResult(err, latency)
	}
	_ = conn.Close()

	return core.NewResult(core.OK, latency,
		fmt.Sprintf("connected to %s", addr), "")
}
