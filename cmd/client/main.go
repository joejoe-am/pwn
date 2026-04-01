// client is the SOCKS5 proxy side of the tunnel.
//
// Usage:
//
//	go run ./cmd/client                         # use config.yaml
//	go run ./cmd/client -config /etc/pwn.yaml   # custom config
//	go run ./cmd/client -listen :8080            # override listen address
//	go run ./cmd/client -transport github        # use ACK-based GitHub transport
//	go run ./cmd/client -transport github_commit # use commit-based GitHub transport
//	go run ./cmd/client -transport gitlab        # use GitLab commit transport
package main

import (
	"flag"
	"log"

	"pwn/internal/config"
	"pwn/internal/logger"
	"pwn/internal/proxy"
	"pwn/internal/transport"
	transportgithub "pwn/internal/transport/github"
	transportgitlab "pwn/internal/transport/gitlab"
	"pwn/internal/tunnel"
)

func main() {
	cfgFile := flag.String("config", "config.yaml", "path to YAML config file")
	fListen := flag.String("listen", "", "override client.listen")
	fTransport := flag.String("transport", "", "override transport: github | github_commit | gitlab")
	fCodec := flag.String("codec", "", "override codec: base64 | raw")
	fTimeout := flag.Duration("timeout", 0, "override client.timeout")
	fDebug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	cfg, err := config.Load(*cfgFile)
	if err != nil {
		log.Fatalf("[client] config: %v", err)
	}

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			cfg.Client.Listen = *fListen
		case "transport":
			cfg.Transport = *fTransport
		case "codec":
			cfg.Codec = *fCodec
		case "timeout":
			cfg.Client.Timeout = config.Duration{Duration: *fTimeout}
		case "debug":
			cfg.Debug = *fDebug
		}
	})

	logger.SetDebug(cfg.Debug)

	log.Printf("[client] transport=%s  codec=%s  listen=%s  timeout=%s",
		cfg.Transport, cfg.Codec, cfg.Client.Listen, cfg.Client.Timeout)

	codec, err := transport.ResolveCodec(cfg.Codec)
	if err != nil {
		log.Fatalf("[client] %v", err)
	}

	tp := buildTransport(cfg, codec, true)

	sessions := tunnel.NewSessionManager()
	done := make(chan struct{})
	tn := tunnel.New(tp, sessions)
	tn.Start(done)
	proxy.Run(cfg.Client.Listen, proxy.Config{
		Username: cfg.Client.Username,
		Password: cfg.Client.Password,
		MaxConns: cfg.Client.MaxConns,
	}, tn)
}

func buildTransport(cfg *config.Config, codec transport.Codec, clientSide bool) transport.Transport {
	timeout := cfg.Client.Timeout
	if !clientSide {
		timeout = cfg.Server.Timeout
	}

	switch cfg.Transport {
	case "", "github", "github_commit":
		sendFile, recvFile := cfg.GitHub.UpFile, cfg.GitHub.DownFile
		sendBranch, recvBranch := cfg.GitHub.EffectiveUpBranch(), cfg.GitHub.EffectiveDownBranch()
		if !clientSide {
			sendFile, recvFile = cfg.GitHub.DownFile, cfg.GitHub.UpFile
			sendBranch, recvBranch = recvBranch, sendBranch
		}
		ghCfg := transportgithub.Config{
			Owner:          cfg.GitHub.Owner,
			Repo:           cfg.GitHub.Repo,
			SendBranch:     sendBranch,
			RecvBranch:     recvBranch,
			SendFile:       sendFile,
			RecvFile:       recvFile,
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
		log.Printf("[%s] %s  owner=%s  repo=%s  up=%s@%s  down=%s@%s  coalesce=%s  poll=%s",
			side(clientSide), cfg.Transport,
			cfg.GitHub.Owner, cfg.GitHub.Repo,
			sendFile, sendBranch, recvFile, recvBranch,
			cfg.GitHub.CoalesceWindow, cfg.GitHub.PollInterval)
		return tp

	case "gitlab":
		sendFile, recvFile := cfg.GitLab.UpFile, cfg.GitLab.DownFile
		sendBranch, recvBranch := cfg.GitLab.EffectiveUpBranch(), cfg.GitLab.EffectiveDownBranch()
		if !clientSide {
			sendFile, recvFile = cfg.GitLab.DownFile, cfg.GitLab.UpFile
			sendBranch, recvBranch = recvBranch, sendBranch
		}
		glCfg := transportgitlab.Config{
			BaseURL:        cfg.GitLab.BaseURL,
			Project:        cfg.GitLab.Project,
			Token:          cfg.GitLab.Token,
			SendFile:       sendFile,
			RecvFile:       recvFile,
			SendBranch:     sendBranch,
			RecvBranch:     recvBranch,
			CoalesceWindow: cfg.GitLab.CoalesceWindow.Duration,
			PollInterval:   cfg.GitLab.PollInterval.Duration,
			MaxRetries:     cfg.GitLab.MaxRetries,
		}
		log.Printf("[%s] gitlab  project=%s  up=%s@%s  down=%s@%s  coalesce=%s  poll=%s",
			side(clientSide),
			cfg.GitLab.Project,
			sendFile, sendBranch, recvFile, recvBranch,
			cfg.GitLab.CoalesceWindow, cfg.GitLab.PollInterval)
		return transportgitlab.New(glCfg, codec)

	default:
		log.Fatalf("unknown transport %q – supported: github, github_commit, gitlab", cfg.Transport)
		return nil
	}
}

func side(clientSide bool) string {
	if clientSide {
		return "client"
	}
	return "server"
}
