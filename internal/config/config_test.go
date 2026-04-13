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
			t.Errorf("expected type 'none', got %q", auth.Type)
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
			t.Errorf("expected default header 'X-API-Key', got %q", auth.Header)
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
			t.Errorf("expected default header 'Authorization', got %q", auth.Header)
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
			t.Errorf("expected header 'X-Custom-Key', got %q", auth.Header)
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
		err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("defaults empty server addr", func(t *testing.T) {
		cfg := &Config{Checks: []Check{}}
		_ = cfg.validate()
		if cfg.Server.Addr != ":8080" {
			t.Errorf("expected default addr ':8080', got %q", cfg.Server.Addr)
		}
	})

	t.Run("defaults empty log level", func(t *testing.T) {
		cfg := &Config{Checks: []Check{}}
		_ = cfg.validate()
		if cfg.Log.Level != "info" {
			t.Errorf("expected default log level 'info', got %q", cfg.Log.Level)
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
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for duplicate check IDs")
		}
	})

	t.Run("empty check ID → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "", Type: core.TypePortBlock},
			},
		}
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for empty check ID")
		}
	})

	t.Run("empty check type → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "test", Type: ""},
			},
		}
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for empty check type")
		}
	})

	t.Run("invalid target → error", func(t *testing.T) {
		cfg := &Config{
			Checks: []Check{
				{ID: "bad", Type: core.TypePortBlock, Target: core.Target{Host: "", Port: 0}},
			},
		}
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for invalid target")
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
		err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
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
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for zero requests per second")
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
		err := cfg.validate()
		if err == nil {
			t.Error("expected error for zero burst")
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
		err := cfg.validate()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
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
			t.Errorf("expected ID 'test', got %q", req.ID)
		}
		if req.Type != core.TypePortBlock {
			t.Errorf("expected type port_blocking, got %s", req.Type)
		}
		if req.Timeout != 5*time.Second {
			t.Errorf("expected timeout 5s, got %v", req.Timeout)
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
			t.Errorf("expected default timeout 10s, got %v", req.Timeout)
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
		t.Errorf("expected %q, got %q", expected, string(data))
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
			t.Errorf("expected 5s, got %v", d)
		}
	})

	t.Run("valid complex duration", func(t *testing.T) {
		var d Duration
		err := json.Unmarshal([]byte(`"1m30s"`), &d)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d != Duration(90*time.Second) {
			t.Errorf("expected 90s, got %v", d)
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
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Server.Addr != ":9090" {
			t.Errorf("expected addr ':9090', got %q", cfg.Server.Addr)
		}
		if cfg.Log.Level != "debug" {
			t.Errorf("expected log level 'debug', got %q", cfg.Log.Level)
		}
	})

	t.Run("nonexistent file → error", func(t *testing.T) {
		_, err := Load("/nonexistent/path/config.json")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON → error", func(t *testing.T) {
		path := writeTempFile(t, `{not valid json}`)
		_, err := Load(path)
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
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Checks) != 1 {
			t.Errorf("expected 1 check, got %d", len(cfg.Checks))
		}
		if cfg.Checks[0].ID != "check1" {
			t.Errorf("expected check ID 'check1', got %q", cfg.Checks[0].ID)
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
			t.Errorf("expected CAFile '/path/to/ca.pem', got %q", cfg.CAFile)
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
			t.Errorf("expected CAFile '/ca.pem', got %q", cfg.CAFile)
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
