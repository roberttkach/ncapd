package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/roberttkach/ncapd/internal/core"
)

func TestAuth_Validate(t *testing.T) {
	t.Run("empty type defaults to none", func(t *testing.T) {
		auth := &Auth{Type: ""}
		err := auth.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if auth.Type != "none" {
			t.Errorf("type = %q, want 'none'", auth.Type)
		}
	})

	t.Run("none type", func(t *testing.T) {
		auth := &Auth{Type: "none"}
		err := auth.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("api_key valid config", func(t *testing.T) {
		auth := &Auth{Type: "api_key", Keys: []string{"key1"}}
		err := auth.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if auth.Header != "X-API-Key" {
			t.Errorf("header = %q, want 'X-API-Key'", auth.Header)
		}
	})

	t.Run("api_key without keys → error", func(t *testing.T) {
		auth := &Auth{Type: "api_key"}
		err := auth.Validate()
		if err == nil {
			t.Error("expected error for api_key without keys")
		}
	})

	t.Run("bearer_token valid config", func(t *testing.T) {
		auth := &Auth{Type: "bearer_token", Keys: []string{"token1"}}
		err := auth.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if auth.Header != "Authorization" {
			t.Errorf("header = %q, want 'Authorization'", auth.Header)
		}
	})

	t.Run("bearer_token without keys → error", func(t *testing.T) {
		auth := &Auth{Type: "bearer_token"}
		err := auth.Validate()
		if err == nil {
			t.Error("expected error for bearer_token without keys")
		}
	})

	t.Run("unknown type → error", func(t *testing.T) {
		auth := &Auth{Type: "unknown"}
		err := auth.Validate()
		if err == nil {
			t.Error("expected error for unknown auth type")
		}
	})

	t.Run("custom header preserved", func(t *testing.T) {
		auth := &Auth{Type: "api_key", Keys: []string{"key1"}, Header: "X-Custom-Key"}
		err := auth.Validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if auth.Header != "X-Custom-Key" {
			t.Errorf("header = %q, want 'X-Custom-Key'", auth.Header)
		}
	})
}

func TestAuth_CheckKey(t *testing.T) {
	t.Run("valid key", func(t *testing.T) {
		auth := &Auth{Keys: []string{"secret"}}
		if !auth.CheckKey("secret") {
			t.Error("expected CheckKey to return true for valid key")
		}
	})

	t.Run("invalid key", func(t *testing.T) {
		auth := &Auth{Keys: []string{"secret"}}
		if auth.CheckKey("wrong") {
			t.Error("expected CheckKey to return false for invalid key")
		}
	})

	t.Run("multiple keys", func(t *testing.T) {
		auth := &Auth{Keys: []string{"key1", "key2", "key3"}}
		if !auth.CheckKey("key2") {
			t.Error("expected CheckKey to return true for second key")
		}
		if auth.CheckKey("key4") {
			t.Error("expected CheckKey to return false for unknown key")
		}
	})

	t.Run("empty keys", func(t *testing.T) {
		auth := &Auth{Keys: []string{}}
		if auth.CheckKey("anything") {
			t.Error("expected CheckKey to return false with no keys")
		}
	})
}

func TestTLS_Enabled(t *testing.T) {
	tests := []struct {
		name    string
		tls     TLS
		enabled bool
	}{
		{"empty", TLS{}, false},
		{"cert only", TLS{CertFile: "/tmp/cert.pem"}, false},
		{"key only", TLS{KeyFile: "/tmp/key.pem"}, false},
		{"both", TLS{CertFile: "/tmp/cert.pem", KeyFile: "/tmp/key.pem"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tls.Enabled(); got != tt.enabled {
				t.Errorf("Enabled() = %v, want %v", got, tt.enabled)
			}
		})
	}
}

func TestConfig_validate(t *testing.T) {
	t.Run("valid minimal config", func(t *testing.T) {
		cfg := &Config{
			Server: Server{Addr: ":8080"},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("defaults empty server addr", func(t *testing.T) {
		cfg := &Config{Checks: []Check{}}
		warnings, _ := cfg.validate()
		if cfg.Server.Addr != ":8080" {
			t.Errorf("addr = %q, want ':8080'", cfg.Server.Addr)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("defaults empty log level", func(t *testing.T) {
		cfg := &Config{Checks: []Check{}}
		warnings, _ := cfg.validate()
		if cfg.Log.Level != "info" {
			t.Errorf("log level = %q, want 'info'", cfg.Log.Level)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("duplicate check IDs → error", func(t *testing.T) {
		cfg := &Config{
			Server: Server{Addr: ":8080"},
			Log:    Log{Level: "info"},
			Checks: []Check{
				{ID: "dup", Type: core.TypePortBlock, Target: core.Target{Host: "example.com", Port: 443}},
				{ID: "dup", Type: core.TypeDNSFilter, Target: core.Target{Host: "google.com"}},
			},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for duplicate check IDs")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("empty check ID → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "", Type: core.TypePortBlock},
			},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for empty check ID")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("empty check type → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "test", Type: ""},
			},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for empty check type")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("invalid target → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "bad", Type: core.TypePortBlock, Target: core.Target{Host: "", Port: 0}},
			},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for invalid target")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("valid rate limit config", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				Addr: ":8080",
				RateLimit: RateLimit{
					Enabled:           true,
					RequestsPerSecond: 10,
					Burst:             5,
				},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("zero requests per second → error", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				Addr: ":8080",
				RateLimit: RateLimit{
					Enabled:           true,
					RequestsPerSecond: 0,
					Burst:             5,
				},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for zero requests per second")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("zero burst → error", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				Addr: ":8080",
				RateLimit: RateLimit{
					Enabled:           true,
					RequestsPerSecond: 10,
					Burst:             0,
				},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for zero burst")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("rate limit disabled → no validation needed", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				RateLimit: RateLimit{
					Enabled:           false,
					RequestsPerSecond: 0,
					Burst:             0,
				},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("valid allowed_source_ips", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				AllowedSourceIPs: []string{"10.0.0.0/8", "192.168.1.0/24"},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("invalid CIDR → error", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				AllowedSourceIPs: []string{"not-a-cidr"},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err == nil {
			t.Error("expected error for invalid CIDR")
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty on error", warnings)
		}
	})

	t.Run("master TLS warning recorded", func(t *testing.T) {
		cfg := &Config{
			Server: Server{
				Master:    "master:50051",
				MasterTLS: MasterTLS{Enabled: false},
			},
			Log:    Log{Level: "info"},
			Checks: []Check{},
		}
		warnings, err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(warnings) != 1 {
			t.Errorf("warnings = %v, want 1 warning", warnings)
		}
		if !cfg.Server.MasterTLS.Enabled {
			t.Error("expected MasterTLS.Enabled to be set to true")
		}
	})
}

func TestCheck_ToReq(t *testing.T) {
	t.Run("with explicit timeout", func(t *testing.T) {
		ch := Check{
			ID:      "test",
			Type:    core.TypePortBlock,
			Target:  core.Target{Host: "example.com", Port: 443},
			Timeout: Duration(5 * time.Second),
		}
		req := ch.ToReq()

		if req.ID != "test" {
			t.Errorf("ID = %q, want 'test'", req.ID)
		}
		if req.Type != core.TypePortBlock {
			t.Errorf("type = %s, want port_blocking", req.Type)
		}
		if req.Timeout != 5*time.Second {
			t.Errorf("timeout = %v, want 5s", req.Timeout)
		}
	})

	t.Run("zero timeout defaults to 10s", func(t *testing.T) {
		ch := Check{
			ID:     "test",
			Type:   core.TypePortBlock,
			Target: core.Target{Host: "example.com", Port: 443},
		}
		req := ch.ToReq()

		if req.Timeout != 10*time.Second {
			t.Errorf("timeout = %v, want 10s", req.Timeout)
		}
	})
}

func TestDuration_MarshalJSON(t *testing.T) {
	d := Duration(5 * time.Second)
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `"5s"`
	if string(data) != expected {
		t.Errorf("data = %q, want %q", string(data), expected)
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		var d Duration
		err := json.Unmarshal([]byte(`"5s"`), &d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != Duration(5*time.Second) {
			t.Errorf("duration = %v, want 5s", d)
		}
	})

	t.Run("valid complex duration", func(t *testing.T) {
		var d Duration
		err := json.Unmarshal([]byte(`"1m30s"`), &d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != Duration(90*time.Second) {
			t.Errorf("duration = %v, want 90s", d)
		}
	})

	t.Run("invalid duration → error", func(t *testing.T) {
		var d Duration
		err := json.Unmarshal([]byte(`"invalid"`), &d)
		if err == nil {
			t.Error("expected error for invalid duration")
		}
	})

	t.Run("non-string JSON → error", func(t *testing.T) {
		var d Duration
		err := json.Unmarshal([]byte(`123`), &d)
		if err == nil {
			t.Error("expected error for non-string JSON")
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("valid config file", func(t *testing.T) {
		content := `{
			"server": {"addr": ":9090"},
			"log": {"level": "debug"},
			"scheduler": {"enabled": false},
			"checks": []
		}`
		path := writeTempFile(t, content)
		cfg, warnings, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Server.Addr != ":9090" {
			t.Errorf("addr = %q, want ':9090'", cfg.Server.Addr)
		}
		if cfg.Log.Level != "debug" {
			t.Errorf("log level = %q, want 'debug'", cfg.Log.Level)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})

	t.Run("nonexistent file → error", func(t *testing.T) {
		_, _, err := Load("/nonexistent/path/config.json")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON → error", func(t *testing.T) {
		path := writeTempFile(t, `{not valid json}`)
		_, _, err := Load(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("valid config with checks", func(t *testing.T) {
		content := `{
			"server": {"addr": ":8080"},
			"log": {"level": "info"},
			"scheduler": {"enabled": true},
			"checks": [
				{
					"id": "check1",
					"type": "port_blocking",
					"target": {"host": "example.com", "port": 443},
					"timeout": "10s",
					"schedule": "0 */5 * * * *"
				}
			]
		}`
		path := writeTempFile(t, content)
		cfg, warnings, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Checks) != 1 {
			t.Errorf("checks = %d, want 1", len(cfg.Checks))
		}
		if cfg.Checks[0].ID != "check1" {
			t.Errorf("check ID = %q, want 'check1'", cfg.Checks[0].ID)
		}
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want empty", warnings)
		}
	})
}

func TestMasterTLS(t *testing.T) {
	t.Run("enabled with all fields", func(t *testing.T) {
		cfg := MasterTLS{
			Enabled:            true,
			InsecureSkipVerify: false,
			CAFile:             "/path/to/ca.pem",
			CertFile:           "/path/to/cert.pem",
			KeyFile:            "/path/to/key.pem",
		}
		if !cfg.Enabled {
			t.Error("expected Enabled to be true")
		}
		if cfg.CAFile != "/path/to/ca.pem" {
			t.Errorf("CAFile = %q, want '/path/to/ca.pem'", cfg.CAFile)
		}
	})

	t.Run("disabled by default", func(t *testing.T) {
		cfg := MasterTLS{}
		if cfg.Enabled {
			t.Error("expected Enabled to be false by default")
		}
	})

	t.Run("parsed from JSON", func(t *testing.T) {
		jsonStr := `{
			"enabled": true,
			"insecure_skip_verify": true,
			"ca_file": "/ca.pem",
			"cert_file": "/cert.pem",
			"key_file": "/key.pem"
		}`
		var cfg MasterTLS
		if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Enabled {
			t.Error("expected Enabled to be true")
		}
		if !cfg.InsecureSkipVerify {
			t.Error("expected InsecureSkipVerify to be true")
		}
		if cfg.CAFile != "/ca.pem" {
			t.Errorf("CAFile = %q, want '/ca.pem'", cfg.CAFile)
		}
	})
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
