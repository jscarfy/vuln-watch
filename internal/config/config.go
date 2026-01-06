package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Source struct {
	Name      string    `yaml:"name"`
	Ecosystem string    `yaml:"ecosystem"`
	Packages  []Package `yaml:"packages"`
}

type Package struct {
	ID      string `yaml:"id"`
	Name    string `yaml:"name"`
	PURL    string `yaml:"purl"`
	Version string `yaml:"version"`
}

func Load(configPath string) (*Config, error) {
	var config Config
	viper.SetConfigFile(configPath)

	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to read config file %s, %v", configPath, err)
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal config into struct, %v", err)
	}

	return &config, nil
}

type Config struct {
	Sources []Source `yaml:"sources"`
}
