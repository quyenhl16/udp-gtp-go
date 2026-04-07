package config

import "time"

func Default() AppConfig {
	return AppConfig{
		App: AppMetaConfig{
			Name:    "udp-gtp-go",
			Env:     "dev",
			Version: "dev",
		},
		Listen: ListenConfig{
			Network: "udp",
			Host:    "0.0.0.0",
			Port:    2152,
		},
		ReusePort: ReusePortConfig{
			Enabled:         true,
			SocketCount:     5,
			S11Weight:       4,
			S10Weight:       1,
			RecvBufferBytes: 4 * 1024 * 1024,
			SendBufferBytes: 4 * 1024 * 1024,
		},
		EBPF: EBPFConfig{
			Enabled:             true,
			PinPath:             "/sys/fs/bpf/udp-gtp-go",
			S11MessageType:      32,
			S10MessageType:      128,
			AllowKernelFallback: true,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Address: ":9090",
			Path:    "/metrics",
		},
		Runtime: RuntimeConfig{
			ReadTimeout:         0,
			WriteTimeout:        0,
			ShutdownGracePeriod: 5 * time.Second,
			LogPackets:          false,
		},
	}
}