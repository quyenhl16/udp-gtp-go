package config

import (
	"encoding/json"
	"fmt"
	"os"
)

func LoadFromFile(path string) (AppConfig, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		return AppConfig{}, fmt.Errorf("read config file %q: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return AppConfig{}, fmt.Errorf("unmarshal config file %q: %w", path, err)
	}

	cfg.Normalize()

	if err := cfg.Validate(); err != nil {
		return AppConfig{}, fmt.Errorf("validate config file %q: %w", path, err)
	}

	return cfg, nil
}