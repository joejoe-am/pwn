// server is the relay side of the tunnel.
//
// Usage:
//
//	go run ./cmd/server                         # use config.yaml
//	go run ./cmd/server -config /etc/pwn.yaml   # custom config
//	go run ./cmd/server -transport github        # use ACK-based GitHub transport
//	go run ./cmd/server -transport github_commit # use commit-based GitHub transport
package main

import (
	"flag"
	"log"

	"pwn/internal/config"
	"pwn/internal/logger"
	"pwn/internal/relay"
	"pwn/internal/transport"
	transportgithub "pwn/internal/transport/github"
	"pwn/internal/tunnel"
)

func main() {
	cfgFile    := flag.String("config",    "config.yaml", "path to YAML config file")
	fTransport := flag.String("transport", "",            "override transport: github | github_commit")
	fCodec     := flag.String("codec",     "",            "override codec: base64 | raw")
	fTimeout   := flag.Duration("timeout", 0,             "override server.timeout")
	fDebug     := flag.Bool("debug",       false,         "enable debug logging")
	flag.Parse()

	cfg, err := config.Load(*cfgFile)
	if err != nil {
		log.Fatalf("[server] config: %v", err)
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "transport": cfg.Transport = *fTransport
		case "codec":     cfg.Codec = *fCodec
		case "timeout":   cfg.Server.Timeout = config.Duration{Duration: *fTimeout}
		case "debug":     cfg.Debug = *fDebug
		}
	})

	logger.SetDebug(cfg.Debug)

	log.Printf("[server] transport=%s  codec=%s  timeout=%s",
		cfg.Transport, cfg.Codec, cfg.Server.Timeout)

	codec, err := transport.ResolveCodec(cfg.Codec)
	if err != nil {
		log.Fatalf("[server] %v", err)
	}

	tp := buildTransport(cfg, codec)

	sessions := tunnel.NewSessionManager()
	done := make(chan struct{})
	tn := tunnel.New(tp, sessions)
	tn.Start(done)
	relay.Run(tn)
}

func buildTransport(cfg *config.Config, codec transport.Codec) transport.Transport {
	timeout := cfg.Server.Timeout

	switch cfg.Transport {
	case "", "github", "github_commit":
		ghCfg := transportgithub.Config{
			Owner:          cfg.GitHub.Owner,
			Repo:           cfg.GitHub.Repo,
			SendBranch:     cfg.GitHub.EffectiveDownBranch(),
			RecvBranch:     cfg.GitHub.EffectiveUpBranch(),
			SendFile:       cfg.GitHub.DownFile,
			RecvFile:       cfg.GitHub.UpFile,
			Token:          cfg.GitHub.Token,
			CoalesceWindow: cfg.GitHub.CoalesceWindow.Duration,
			PollInterval:   cfg.GitHub.PollInterval.Duration,
			SendTimeout:    cfg.GitHub.EffectiveSendTimeout(timeout),
			MaxRetries:     cfg.GitHub.MaxRetries,
		}
		var tp transport.Transport
		if cfg.Transport == "github_commit" || cfg.Transport == "" {
			tp = transportgithub.NewCommit(ghCfg, codec)
		} else {
			tp = transportgithub.New(ghCfg, codec)
		}
		log.Printf("[server] %s  owner=%s  repo=%s  send=%s@%s  recv=%s@%s  coalesce=%s  poll=%s",
			cfg.Transport,
			cfg.GitHub.Owner, cfg.GitHub.Repo,
			cfg.GitHub.DownFile, cfg.GitHub.EffectiveDownBranch(),
			cfg.GitHub.UpFile, cfg.GitHub.EffectiveUpBranch(),
			cfg.GitHub.CoalesceWindow, cfg.GitHub.PollInterval)
		return tp

	default:
		log.Fatalf("unknown transport %q – supported: github, github_commit", cfg.Transport)
		return nil
	}
}
