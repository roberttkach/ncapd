package config

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
	"github.com/roberttkach/ncapd/internal/validate"
)

type Config struct {
	Server    Server          `json:"server"`
	Log       Log             `json:"log"`
	Scheduler SchedulerConfig `json:"scheduler"`
	Checks    []Check         `json:"checks"`
}

type Check struct {
	ID       string      `json:"id"`
	Type     core.Type   `json:"type"`
	Target   core.Target `json:"target"`
	Timeout  Duration    `json:"timeout"`
	Schedule string      `json:"schedule"`
}

type Server struct {
	Addr             string        `json:"addr"`
	Node             string        `json:"node_id"`
	TLS              TLS           `json:"tls"`
	Master           string        `json:"master_addr"`
	MasterTLS        MasterTLS     `json:"master_tls"`
	Auth             Auth          `json:"auth"`
	AuthRateLimit    AuthRateLimit `json:"auth_rate_limit"`
	RateLimit        RateLimit     `json:"rate_limit"`
	MaxResults       *int          `json:"max_results"`
	SkipVerify       *bool         `json:"skip_verify"`
	RunCooldown      Duration      `json:"run_cooldown"`
	AllowedSourceIPs []string      `json:"allowed_source_ips"`
	Audit            Audit         `json:"audit"`
}

type Auth struct {
	Type   string   `json:"type"`
	Keys   []string `json:"keys"`
	Header string   `json:"header"`
}

type AuthRateLimit struct {
	Enabled       bool `json:"enabled"`
	MaxFailures   int  `json:"max_failures"`
	WindowSeconds int  `json:"window_seconds"`
	BanSeconds    int  `json:"ban_seconds"`
}

type RateLimit struct {
	Enabled           bool    `json:"enabled"`
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
}

type TLS struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
}

type MasterTLS struct {
	Enabled            bool   `json:"enabled"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	CAFile             string `json:"ca_file"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
}

type Audit struct {
	Enabled bool `json:"enabled"`
}
type Log struct {
	Level string `json:"level"`
}
type SchedulerConfig struct {
	Enabled *bool `json:"enabled"`
}
type Duration time.Duration

func Load(path string) (*Config, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	warnings, err := cfg.validate()
	if err != nil {
		return nil, nil, err
	}
	return &cfg, warnings, nil
}

func (a *Auth) Validate() error {
	switch a.Type {
	case "", "none":
		a.Type = "none"
		return nil
	case "api_key":
		if a.Header == "" {
			a.Header = "X-API-Key"
		}
		if len(a.Keys) == 0 {
			return fmt.Errorf("config: auth type %q requires keys", a.Type)
		}
	case "bearer_token":
		if a.Header == "" {
			a.Header = "Authorization"
		}
		if len(a.Keys) == 0 {
			return fmt.Errorf("config: auth type %q requires tokens", a.Type)
		}
	default:
		return fmt.Errorf("config: unknown auth type %q", a.Type)
	}
	return nil
}

func (a *Auth) CheckKey(provided string) bool {
	for _, key := range a.Keys {
		if subtle.ConstantTimeCompare([]byte(provided), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

func (t TLS) Enabled() bool { return t.CertFile != "" && t.KeyFile != "" }

func (c Check) ToReq() core.Request {
	t := time.Duration(c.Timeout)
	if t == 0 {
		t = 10 * time.Second
	}
	return core.Request{ID: c.ID, Type: c.Type, Target: c.Target, Timeout: t}
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration: %w", err)
	}
	*d = Duration(v)
	return nil
}

func (c *Config) validate() ([]string, error) {
	var warnings []string

	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Scheduler.Enabled == nil {
		v := true
		c.Scheduler.Enabled = &v
	}
	if c.Server.SkipVerify == nil {
		v := false
		c.Server.SkipVerify = &v
	}
	if c.Server.RunCooldown == 0 {
		c.Server.RunCooldown = Duration(10 * time.Second)
	}
	if c.Server.MaxResults == nil {
		v := 1000
		c.Server.MaxResults = &v
	} else if *c.Server.MaxResults <= 0 {
		return nil, fmt.Errorf("config: max_results must be positive")
	}
	if err := c.Server.Auth.Validate(); err != nil {
		return nil, err
	}
	if c.Server.RateLimit.Enabled {
		if c.Server.RateLimit.RequestsPerSecond <= 0 || c.Server.RateLimit.RequestsPerSecond > 50 {
			return nil, fmt.Errorf("config: rate_limit.requests_per_second must be 1–50")
		}
		if c.Server.RateLimit.Burst < 1 || c.Server.RateLimit.Burst > 100 {
			return nil, fmt.Errorf("config: rate_limit.burst must be 1–100")
		}
	}
	if c.Server.AuthRateLimit.Enabled {
		if c.Server.AuthRateLimit.MaxFailures <= 0 {
			c.Server.AuthRateLimit.MaxFailures = 10
		}
		if c.Server.AuthRateLimit.WindowSeconds <= 0 {
			c.Server.AuthRateLimit.WindowSeconds = 300
		}
		if c.Server.AuthRateLimit.BanSeconds <= 0 {
			c.Server.AuthRateLimit.BanSeconds = 60
		}
		if c.Server.AuthRateLimit.MaxFailures > 20 {
			return nil, fmt.Errorf("config: auth_rate_limit.max_failures exceeds max (20)")
		}
		if c.Server.AuthRateLimit.WindowSeconds > 600 {
			return nil, fmt.Errorf("config: auth_rate_limit.window_seconds exceeds max (600)")
		}
		if c.Server.AuthRateLimit.BanSeconds > 600 {
			return nil, fmt.Errorf("config: auth_rate_limit.ban_seconds exceeds max (600)")
		}
	}
	for i, cidr := range c.Server.AllowedSourceIPs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return nil, fmt.Errorf("config: allowed_source_ips[%d]: invalid CIDR %q", i, cidr)
		}
	}
	if c.Server.Master != "" && !c.Server.MasterTLS.Enabled {
		c.Server.MasterTLS.Enabled = true
		warnings = append(warnings, "master TLS was disabled in config, enabling by default for security")
	}
	seen := make(map[string]struct{}, len(c.Checks))
	for i, ch := range c.Checks {
		if ch.ID == "" {
			return nil, fmt.Errorf("config: checks[%d]: id required", i)
		}
		if ch.Type == "" {
			return nil, fmt.Errorf("config: check %q: type required", ch.ID)
		}
		if _, dup := seen[ch.ID]; dup {
			return nil, fmt.Errorf("config: duplicate check id %q", ch.ID)
		}
		seen[ch.ID] = struct{}{}
		if err := validate.Target(ch.Target, ch.Type); err != nil {
			return nil, fmt.Errorf("config: check %q: %w", ch.ID, err)
		}
	}
	return warnings, nil
}
