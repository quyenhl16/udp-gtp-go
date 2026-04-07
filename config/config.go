package config

import "time"

type AppConfig struct {
	App       AppMetaConfig    `json:"app"`
	Listen    ListenConfig     `json:"listen"`
	ReusePort ReusePortConfig  `json:"reuseport"`
	EBPF      EBPFConfig       `json:"ebpf"`
	Metrics   MetricsConfig    `json:"metrics"`
	Runtime   RuntimeConfig    `json:"runtime"`
}

type AppMetaConfig struct {
	Name    string `json:"name"`
	Env     string `json:"env"`
	Version string `json:"version"`
}

type ListenConfig struct {
	Network string `json:"network"` // udp, udp4, udp6
	Host    string `json:"host"`
	Port    int    `json:"port"`
}

type ReusePortConfig struct {
	Enabled     bool `json:"enabled"`
	SocketCount int  `json:"socket_count"`

	// Tỉ lệ pool logic cho classifier.
	// Ví dụ S11=4, S10=1.
	S11Weight int `json:"s11_weight"`
	S10Weight int `json:"s10_weight"`

	RecvBufferBytes int `json:"recv_buffer_bytes"`
	SendBufferBytes int `json:"send_buffer_bytes"`
}

type EBPFConfig struct {
	Enabled bool   `json:"enabled"`
	PinPath string `json:"pin_path"`

	// MessageType giả lập dùng để classify.
	S11MessageType uint8 `json:"s11_message_type"`
	S10MessageType uint8 `json:"s10_message_type"`

	// Cho phép fallback về kernel hashing nếu selector không chọn được.
	AllowKernelFallback bool `json:"allow_kernel_fallback"`
}

type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Path    string `json:"path"`
}

type RuntimeConfig struct {
	ReadTimeout          time.Duration `json:"read_timeout"`
	WriteTimeout         time.Duration `json:"write_timeout"`
	ShutdownGracePeriod  time.Duration `json:"shutdown_grace_period"`
	LogPackets           bool          `json:"log_packets"`
}