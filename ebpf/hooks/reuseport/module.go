package reuseport

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"

	artifact "github.com/quyenhl16/udp-gtp-go/ebpf/artifacts/reuseport"
	"github.com/quyenhl16/udp-gtp-go/ebpf/contracts"
	ebpfmaps "github.com/quyenhl16/udp-gtp-go/ebpf/maps"
)

// Module is the runtime adapter for the reuseport selector.
type Module struct {
	bundle *artifact.Bundle
}

// New creates an unloaded reuseport module.
func New() *Module {
	return &Module{}
}

// Name returns the logical module name.
func (m *Module) Name() string {
	return "reuseport"
}

// Load loads the generated reuseport object.
func (m *Module) Load() error {
	bundle, err := artifact.Load(nil)
	if err != nil {
		return err
	}

	m.bundle = bundle
	return nil
}

// LoadWithOptions loads the generated reuseport object with explicit artifact options.
func (m *Module) LoadWithOptions(opts *artifact.LoadOptions) error {
	bundle, err := artifact.Load(opts)
	if err != nil {
		return err
	}

	m.bundle = bundle
	return nil
}

// Close releases all loaded resources.
func (m *Module) Close() error {
	if m == nil || m.bundle == nil {
		return nil
	}

	return m.bundle.Close()
}

// UpdateConfig pushes runtime configuration to config_map.
func (m *Module) UpdateConfig(cfg Config) error {
	if m == nil || m.bundle == nil || m.bundle.ConfigMap == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}

	key := uint32(0)
	value := bpfConfig{
		S11MessageType:      cfg.S11MessageType,
		S10MessageType:      cfg.S10MessageType,
		AllowKernelFallback: boolToUint8(cfg.AllowKernelFallback),
		S11PoolBase:         cfg.S11PoolBase,
		S11PoolSize:         cfg.S11PoolSize,
		S10PoolBase:         cfg.S10PoolBase,
		S10PoolSize:         cfg.S10PoolSize,
		FallbackPoolBase:    cfg.FallbackPoolBase,
		FallbackPoolSize:    cfg.FallbackPoolSize,
	}

	return ebpfmaps.UpdateArrayValue(m.bundle.ConfigMap, key, &value)
}

// SyncSockArray writes socket file descriptors into sock_map.
func (m *Module) SyncSockArray(group contracts.SocketGroup) error {
	if m == nil || m.bundle == nil || m.bundle.SockMap == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}
	if group == nil {
		return fmt.Errorf("socket group is nil")
	}

	return ebpfmaps.SyncSockArray(m.bundle.SockMap, group.FDs())
}

// Attach binds the selector program to the socket group.
func (m *Module) Attach(group contracts.SocketGroup) error {
	if m == nil || m.bundle == nil || m.bundle.Selector == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}
	if group == nil {
		return fmt.Errorf("socket group is nil")
	}

	fd, err := group.FD(0)
	if err != nil {
		return fmt.Errorf("get attach socket fd: %w", err)
	}

	return attachProgram(fd, m.bundle.Selector)
}

// Program returns the underlying selector program.
func (m *Module) Program() (*ciliumebpf.Program, error) {
	if m == nil || m.bundle == nil || m.bundle.Selector == nil {
		return nil, fmt.Errorf("reuseport module is not loaded")
	}

	return m.bundle.Selector, nil
}

func boolToUint8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}