package config

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
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
	Addr      string    `json:"addr"`
	Node      string    `json:"node_id"`
	TLS       TLS       `json:"tls"`
	Master    string    `json:"master_addr"`
	MasterTLS MasterTLS `json:"master_tls"`
	Auth      Auth      `json:"auth"`
	RateLimit RateLimit `json:"rate_limit"`
	Audit     Audit     `json:"audit"`
}

type Auth struct {
	Type   string   `json:"type"`
	Keys   []string `json:"keys"`
	Header string   `json:"header"`
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
	Enabled bool `json:"enabled"`
}

type Duration time.Duration

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err = cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
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
			return fmt.Errorf("config: auth type %q requires at least one key", a.Type)
		}
	case "bearer_token":
		if a.Header == "" {
			a.Header = "Authorization"
		}
		if len(a.Keys) == 0 {
			return fmt.Errorf("config: auth type %q requires at least one token", a.Type)
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

func (t TLS) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

func (c Check) ToReq() core.Request {
	t := time.Duration(c.Timeout)
	if t == 0 {
		t = 10 * time.Second
	}
	return core.Request{
		ID:      c.ID,
		Type:    c.Type,
		Target:  c.Target,
		Timeout: t,
	}
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

func (c *Config) validate() error {
	if c.Server.Addr == "" {
		c.Server.Addr = ":8080"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}

	if err := c.Server.Auth.Validate(); err != nil {
		return err
	}

	if c.Server.RateLimit.Enabled {
		if c.Server.RateLimit.RequestsPerSecond <= 0 {
			return fmt.Errorf("config: rate_limit.requests_per_second must be positive")
		}
		if c.Server.RateLimit.Burst < 1 {
			return fmt.Errorf("config: rate_limit.burst must be at least 1")
		}
	}

	seen := make(map[string]struct{}, len(c.Checks))
	for i, ch := range c.Checks {
		if ch.ID == "" {
			return fmt.Errorf("config: checks[%d]: id is required", i)
		}
		if ch.Type == "" {
			return fmt.Errorf("config: check %q: type is required", ch.ID)
		}
		if _, dup := seen[ch.ID]; dup {
			return fmt.Errorf("config: duplicate check id %q", ch.ID)
		}
		seen[ch.ID] = struct{}{}

		if err := validate.Target(ch.Target, ch.Type); err != nil {
			return fmt.Errorf("config: check %q: %w", ch.ID, err)
		}
	}
	return nil
}
