// Package config loads application settings from a YAML file.
// CLI flags always win over the file; the file wins over built-in defaults.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Duration ──────────────────────────────────────────────────────────────────

// Duration wraps time.Duration so YAML can parse strings like "30s", "1m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(v *yaml.Node) error {
	dur, err := time.ParseDuration(v.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", v.Value, err)
	}
	d.Duration = dur
	return nil
}

func (d Duration) MarshalYAML() (interface{}, error) { return d.String(), nil }

// ── Config structs ────────────────────────────────────────────────────────────

// Config is the top-level structure read by both the client and server.
type Config struct {
	// Transport selects the carrier: "github" or "github_commit" (default).
	Transport string `yaml:"transport"`
	// Codec is the wire encoding shared by both sides: "base64" or "raw".
	Codec string `yaml:"codec"`
	// Debug enables verbose debug-level logging when true.
	Debug bool `yaml:"debug"`

	GitHub GitHubConfig `yaml:"github"`
	Client ClientConfig `yaml:"client"`
	Server ServerConfig `yaml:"server"`
}

// GitHubConfig describes the GitHub repository used by the transport.
type GitHubConfig struct {
	// Owner is the GitHub username or organisation, e.g. "joejoe-am".
	Owner string `yaml:"owner"`
	// Repo is the repository name, e.g. "fun-net".
	Repo string `yaml:"repo"`
	// Branch is the default branch, used when up_branch/down_branch are empty.
	Branch string `yaml:"branch"`
	// UpBranch is the branch for client→server traffic (up_file commits).
	// Falls back to Branch when empty.
	UpBranch string `yaml:"up_branch"`
	// DownBranch is the branch for server→client traffic (down_file commits).
	// Falls back to Branch when empty.
	DownBranch string `yaml:"down_branch"`

	// UpFile is the repo-relative path for client→server data.
	UpFile string `yaml:"up_file"`
	// DownFile is the repo-relative path for server→client data.
	DownFile string `yaml:"down_file"`

	// Token is a GitHub Personal Access Token with repo scope.
	Token string `yaml:"token"`

	// CoalesceWindow is how long to accumulate packets before flushing.
	// Larger values pack more data per commit; default 200ms.
	CoalesceWindow Duration `yaml:"coalesce_window"`

	// PollInterval is how often to check for incoming data. Default: 2s.
	PollInterval Duration `yaml:"poll_interval"`

	// SendTimeout is how long to wait for the remote to consume a batch.
	// Only used by the "github" (ACK-based) transport. 0 = use client/server timeout.
	SendTimeout Duration `yaml:"send_timeout"`

	MaxRetries int `yaml:"max_retries"`
}

// EffectiveUpBranch returns UpBranch, falling back to Branch, then "main".
func (g GitHubConfig) EffectiveUpBranch() string {
	if g.UpBranch != "" {
		return g.UpBranch
	}
	if g.Branch != "" {
		return g.Branch
	}
	return "main"
}

// EffectiveDownBranch returns DownBranch, falling back to Branch, then "main".
func (g GitHubConfig) EffectiveDownBranch() string {
	if g.DownBranch != "" {
		return g.DownBranch
	}
	if g.Branch != "" {
		return g.Branch
	}
	return "main"
}

// EffectiveSendTimeout returns SendTimeout, falling back to fallback when zero.
func (g GitHubConfig) EffectiveSendTimeout(fallback Duration) time.Duration {
	if g.SendTimeout.Duration != 0 {
		return g.SendTimeout.Duration
	}
	return fallback.Duration
}

// ClientConfig holds settings for the client (SOCKS5 proxy) side.
type ClientConfig struct {
	Listen  string   `yaml:"listen"`
	Timeout Duration `yaml:"timeout"`

	// Username and Password enable RFC 1929 SOCKS5 authentication.
	// Leave both empty (the default) to allow unauthenticated access.
	Username string `yaml:"username"`
	Password string `yaml:"password"`

	// MaxConns limits the number of concurrent SOCKS5 connections.
	// 0 uses the built-in default (64).
	MaxConns int `yaml:"max_conns"`
}

// ServerConfig holds settings for the server (relay) side.
type ServerConfig struct {
	Timeout Duration `yaml:"timeout"`
}

// ── Defaults & loading ────────────────────────────────────────────────────────

func Defaults() *Config {
	return &Config{
		Transport: "github_commit",
		Codec:     "base64",
		GitHub: GitHubConfig{
			Branch:         "main",
			UpFile:         "packet-ab.txt",
			DownFile:       "packet-ba.txt",
			CoalesceWindow: Duration{200 * time.Millisecond},
			PollInterval:   Duration{2 * time.Second},
			SendTimeout:    Duration{0},
			MaxRetries:     3,
		},
		Client: ClientConfig{
			Listen:  ":1080",
			Timeout: Duration{30 * time.Second},
		},
		Server: ServerConfig{
			Timeout: Duration{30 * time.Second},
		},
	}
}

// Load reads the YAML file at path and merges it on top of Defaults().
// A missing file is not an error – Defaults() is returned so the binary works
// without a config file.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}
