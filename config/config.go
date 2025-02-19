package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

// Config holds settings loaded from a YAML configuration file.
type Config struct {
	// Custom regex patterns for scanning.
	Patterns []string `yaml:"patterns"`
	// List of proxies for rotation (e.g., ["http://127.0.0.1:8080", "socks5://127.0.0.1:1080"]).
	Proxies []string `yaml:"proxies"`
	// Rate limit for requests (e.g., 5 requests per second).
	RateLimit float64 `yaml:"rate_limit"`
}

// LoadConfig loads the YAML configuration from the given file.
// If file is an empty string, it returns a default configuration.
func LoadConfig(file string) (*Config, error) {
	if file == "" {
		return &Config{
			Patterns:  []string{},
			Proxies:   []string{},
			RateLimit: 5,
		}, nil
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
