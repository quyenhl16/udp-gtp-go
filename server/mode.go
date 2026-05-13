package server

import appconfig "github.com/quyenhl16/udp-gtp-go/config"

// Mode defines how the UDP server is started.
type Mode string

const (
	// ModeNormal starts a normal UDP server with one socket.
	ModeNormal Mode = "normal"

	// ModeReusePort starts multiple UDP sockets using SO_REUSEPORT without eBPF.
	ModeReusePort Mode = "reuseport"

	// ModeReusePortEBPF starts multiple UDP sockets using SO_REUSEPORT and eBPF.
	ModeReusePortEBPF Mode = "reuseport_ebpf"
)

// ModeFromConfig derives the server mode from application configuration.
func ModeFromConfig(cfg appconfig.AppConfig) Mode {
	if cfg.ReusePort.Enabled && cfg.EBPF.Enabled {
		return ModeReusePortEBPF
	}

	if cfg.ReusePort.Enabled {
		return ModeReusePort
	}

	return ModeNormal
}