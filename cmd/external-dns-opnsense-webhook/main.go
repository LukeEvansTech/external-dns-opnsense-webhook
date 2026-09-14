package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/config"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/dnsprovider"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/metrics"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/server"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/webhook"
)

var (
	Version = "local"
	Gitsha  = "?"
)

func main() {
	initLogger()
	slog.Info("starting external-dns-opnsense-webhook", "version", Version, "gitsha", Gitsha)

	metrics.New(Version)

	cfg, err := config.Init()
	if err != nil {
		slog.Error("loading configuration", "error", err)
		os.Exit(1)
	}

	prov, err := dnsprovider.Init(&cfg)
	if err != nil {
		slog.Error("initializing provider", "error", err)
		os.Exit(1)
	}

	// The two configurations live in different packages, so this is the only
	// place both timeouts are visible: refuse to start rather than let the
	// server cut off the reply to an apply that is still legitimately running.
	if budget := prov.ApplyBudget(); budget > cfg.ServerWriteTimeout {
		slog.Error("SERVER_WRITE_TIMEOUT must exceed OPNSENSE_APPLY_TIMEOUT plus OPNSENSE_RECONFIGURE_TIMEOUT",
			"server_write_timeout", cfg.ServerWriteTimeout, "apply_budget", budget)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
	)
	defer stop()

	// Listeners must be up before the firewall is contacted: external-dns
	// gives GET / only a few retries at start. Startup runs concurrently and
	// only affects readiness.
	go prov.Startup(ctx)

	if err := server.Run(ctx, &cfg, webhook.New(prov), prov.Ready); err != nil {
		slog.Error("running server", "error", err)
		os.Exit(1)
	}
}

func initLogger() {
	var level slog.Level
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	// AddSource emits the calling function/file/line on every record. That's
	// useful for debugging but doubles the size of routine logs and the same
	// access-log call site appears on every request. Only opt in at debug.
	opts := &slog.HandlerOptions{
		AddSource: level == slog.LevelDebug,
		Level:     level,
	}

	var handler slog.Handler
	if os.Getenv("LOG_FORMAT") == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
}
