package config

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Sources []Source `yaml:"sources"`
	Output  Output   `yaml:"output"`
}

type Source struct {
	Name     string    `yaml:"name"`
	Packages []Package `yaml:"packages"`
}

type Package struct {
	ID        string `yaml:"id"`
	PURL      string `yaml:"purl"`
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
}

type Output struct {
	Format      string `yaml:"format"`       // text | json
	FailOnVuln  bool   `yaml:"fail_on_vuln"` // CI gating
	MinSeverity string `yaml:"min_severity"` // LOW|MEDIUM|HIGH|CRITICAL
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Sources) == 0 {
		return nil, errors.New("config: sources is empty")
	}

	// Defaults
	if cfg.Output.Format == "" {
		cfg.Output.Format = "text"
	}
	if cfg.Output.MinSeverity == "" {
		cfg.Output.MinSeverity = "LOW"
	}

	return &cfg, nil
}
