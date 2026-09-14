// Package dnsprovider constructs the OPNsense provider from the environment.
package dnsprovider

import (
	"fmt"
	"log/slog"

	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/config"
	"github.com/LukeEvansTech/external-dns-opnsense-webhook/internal/opnsense"
	"github.com/caarlos0/env/v11"
)

// Init parses OPNSENSE_* and builds the provider. It performs no I/O.
func Init(_ *config.Config) (*opnsense.Provider, error) {
	cfg := opnsense.Config{}
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("reading opnsense configuration: %w", err)
	}
	p, err := opnsense.NewProvider(&cfg)
	if err != nil {
		return nil, fmt.Errorf("creating opnsense provider: %w", err)
	}
	slog.Info("created opnsense provider", "host", cfg.Host, "domains", cfg.Domains, "add_ptr", cfg.AddPTR)
	return p, nil
}
