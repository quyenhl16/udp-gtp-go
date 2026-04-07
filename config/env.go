package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const EnvPrefix = "UDP_GTP_GO_"

func Load() (AppConfig, error) {
	cfg := Default()
	applyEnv(&cfg)
	cfg.Normalize()

	if err := cfg.Validate(); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func LoadWithFile(path string) (AppConfig, error) {
	cfg, err := LoadFromFile(path)
	if err != nil {
		return AppConfig{}, err
	}

	applyEnv(&cfg)
	cfg.Normalize()

	if err := cfg.Validate(); err != nil {
		return AppConfig{}, err
	}
	return cfg, nil
}

func applyEnv(cfg *AppConfig) {
	if v := os.Getenv(EnvPrefix + "APP_NAME"); v != "" {
		cfg.App.Name = v
	}
	if v := os.Getenv(EnvPrefix + "APP_ENV"); v != "" {
		cfg.App.Env = v
	}
	if v := os.Getenv(EnvPrefix + "APP_VERSION"); v != "" {
		cfg.App.Version = v
	}

	if v := os.Getenv(EnvPrefix + "LISTEN_NETWORK"); v != "" {
		cfg.Listen.Network = v
	}
	if v := os.Getenv(EnvPrefix + "LISTEN_HOST"); v != "" {
		cfg.Listen.Host = v
	}
	if v, ok := getenvInt(EnvPrefix + "LISTEN_PORT"); ok {
		cfg.Listen.Port = v
	}

	if v, ok := getenvBool(EnvPrefix + "REUSEPORT_ENABLED"); ok {
		cfg.ReusePort.Enabled = v
	}
	if v, ok := getenvInt(EnvPrefix + "REUSEPORT_SOCKET_COUNT"); ok {
		cfg.ReusePort.SocketCount = v
	}
	if v, ok := getenvInt(EnvPrefix + "REUSEPORT_S11_WEIGHT"); ok {
		cfg.ReusePort.S11Weight = v
	}
	if v, ok := getenvInt(EnvPrefix + "REUSEPORT_S10_WEIGHT"); ok {
		cfg.ReusePort.S10Weight = v
	}
	if v, ok := getenvInt(EnvPrefix + "REUSEPORT_RECV_BUFFER_BYTES"); ok {
		cfg.ReusePort.RecvBufferBytes = v
	}
	if v, ok := getenvInt(EnvPrefix + "REUSEPORT_SEND_BUFFER_BYTES"); ok {
		cfg.ReusePort.SendBufferBytes = v
	}

	if v, ok := getenvBool(EnvPrefix + "EBPF_ENABLED"); ok {
		cfg.EBPF.Enabled = v
	}
	if v := os.Getenv(EnvPrefix + "EBPF_PIN_PATH"); v != "" {
		cfg.EBPF.PinPath = v
	}
	if v, ok := getenvUint8(EnvPrefix + "EBPF_S11_MESSAGE_TYPE"); ok {
		cfg.EBPF.S11MessageType = v
	}
	if v, ok := getenvUint8(EnvPrefix + "EBPF_S10_MESSAGE_TYPE"); ok {
		cfg.EBPF.S10MessageType = v
	}
	if v, ok := getenvBool(EnvPrefix + "EBPF_ALLOW_KERNEL_FALLBACK"); ok {
		cfg.EBPF.AllowKernelFallback = v
	}

	if v, ok := getenvBool(EnvPrefix + "METRICS_ENABLED"); ok {
		cfg.Metrics.Enabled = v
	}
	if v := os.Getenv(EnvPrefix + "METRICS_ADDRESS"); v != "" {
		cfg.Metrics.Address = v
	}
	if v := os.Getenv(EnvPrefix + "METRICS_PATH"); v != "" {
		cfg.Metrics.Path = v
	}

	if v, ok := getenvBool(EnvPrefix + "RUNTIME_LOG_PACKETS"); ok {
		cfg.Runtime.LogPackets = v
	}
}

func getenvInt(key string) (int, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}

func getenvUint8(key string) (uint8, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return 0, false
	}
	return uint8(n), true
}

func getenvBool(key string) (bool, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return false, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, false
	}
	return b, true
}

func MustLoad() AppConfig {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Errorf("load config: %w", err))
	}
	return cfg
}