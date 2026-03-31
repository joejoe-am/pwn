// server is the relay side of the tunnel.
//
// Usage:
//
//	go run ./cmd/server                         # use config.yaml
//	go run ./cmd/server -config /etc/pwn.yaml   # custom config
//	go run ./cmd/server -transport wiki          # use Wikipedia transport
package main

import (
	"flag"
	"log"

	"pwn/internal/config"
	"pwn/internal/logger"
	"pwn/internal/relay"
	"pwn/internal/transport"
	"pwn/internal/tunnel"

	// Import buildTransport from the client package is not possible (separate
	// binaries), so we inline the same helper here.
	"pwn/internal/transport/filepipe"
	transportgithub "pwn/internal/transport/github"
	"pwn/internal/transport/wiki"
)

func main() {
	cfgFile    := flag.String("config",    "config.yaml", "path to YAML config file")
	fTransport := flag.String("transport", "",            "override transport: filepipe | wiki | github")
	fCodec     := flag.String("codec",     "",            "override codec: base64 | raw")
	fTimeout   := flag.Duration("timeout", 0,             "override server.timeout")
	fUp        := flag.String("up",        "",            "override pipe.up / wiki.up_page")
	fDown      := flag.String("down",      "",            "override pipe.down / wiki.down_page")
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
		case "up":        cfg.Pipe.Up = *fUp; cfg.Wiki.UpPage = *fUp
		case "down":      cfg.Pipe.Down = *fDown; cfg.Wiki.DownPage = *fDown
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

	// server sends to Down, receives from Up
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
	case "", "filepipe":
		// server sends to Down, reads from Up
		fp := filepipe.New(cfg.Pipe.Down, cfg.Pipe.Up, codec)
		fp.SendTimeout = cfg.Pipe.EffectiveSendTimeout(timeout)
		fp.MaxRetries = cfg.Pipe.MaxRetries
		log.Printf("[server] pipe  up=%s  down=%s  retries=%d",
			cfg.Pipe.Up, cfg.Pipe.Down, cfg.Pipe.MaxRetries)
		return fp

	case "wiki":
		// server sends to DownPage, reads from UpPage
		wt := wiki.New(wiki.Config{
			SendPage:     cfg.Wiki.DownPage,
			RecvPage:     cfg.Wiki.UpPage,
			APIEndpoint:  cfg.Wiki.APIEndpoint,
			Cookies:      cfg.Wiki.Cookies,
			PollInterval: cfg.Wiki.PollInterval.Duration,
			SendTimeout:  cfg.Wiki.EffectiveSendTimeout(timeout),
			MaxRetries:   cfg.Wiki.MaxRetries,
		}, codec)
		log.Printf("[server] wiki  up=%s  down=%s  poll=%s",
			cfg.Wiki.UpPage, cfg.Wiki.DownPage, cfg.Wiki.PollInterval)
		return wt

	case "github", "github_commit":
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
		if cfg.Transport == "github_commit" {
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
		log.Fatalf("unknown transport %q – supported: filepipe, wiki, github, github_commit", cfg.Transport)
		return nil
	}
}
