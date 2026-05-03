package reuseport

import (
	"context"
	"fmt"
	"sync"

	artifact "github.com/quyenhl16/udp-gtp-go/ebpf/artifacts/reuseport"
	"github.com/quyenhl16/udp-gtp-go/ebpf/core"
	ebpfmaps "github.com/quyenhl16/udp-gtp-go/ebpf/maps"
	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
)

// Module is the runtime adapter for the reuseport selector.
//
// The module lifecycle is split into:
// - Load: load eBPF objects into the kernel
// - Attach: enable custom steering on the reuseport group
// - Detach: disable custom steering without stopping the server
// - Close: release all owned resources
type Module struct {
	mu sync.Mutex

	lifecycle core.Lifecycle

	bundle *artifact.Bundle
	group  *rpsock.Group

	activeConfig   Config
	disabledConfig Config

	programBound bool
}

// New creates a new reuseport module.
func New() *Module {
	return &Module{
		lifecycle: core.NewLifecycle(),
	}
}

// Name returns the logical module name.
func (m *Module) Name() string {
	return "reuseport"
}

// State returns the current lifecycle state.
func (m *Module) State() core.State {
	return m.lifecycle.State()
}

// IsEnabled reports whether the module is currently attached.
func (m *Module) IsEnabled() bool {
	return m.lifecycle.IsEnabled()
}

// SetGroup sets the reuseport group used by this module.
//
// The group must be configured before Attach is called.
func (m *Module) SetGroup(group *rpsock.Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lifecycle.State() == core.StateAttached {
		return fmt.Errorf("%w: cannot change reuseport group while attached", core.ErrInvalidStateTransition)
	}

	m.group = group
	return nil
}

// SetConfig sets the active runtime configuration used when the module is attached.
//
// This method also prepares the internal "disabled" config used by Detach.
func (m *Module) SetConfig(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lifecycle.State() == core.StateAttached {
		return fmt.Errorf("%w: cannot change reuseport config while attached", core.ErrInvalidStateTransition)
	}

	m.activeConfig = cfg
	m.disabledConfig = buildDisabledConfig(cfg)
	return nil
}

// Load loads the reuseport eBPF artifact into the kernel.
//
// Load is intentionally idempotent for already loaded modules.
func (m *Module) Load(ctx context.Context) error {
	_ = ctx

	m.mu.Lock()
	defer m.mu.Unlock()

	switch m.lifecycle.State() {
	case core.StateLoaded, core.StateAttached, core.StateDetached:
		return nil
	}

	if err := m.lifecycle.ValidateLoad(); err != nil {
		return err
	}

	bundle, err := artifact.Load(nil)
	if err != nil {
		return fmt.Errorf("load reuseport artifact: %w", err)
	}

	m.bundle = bundle
	m.lifecycle.Transition(core.StateLoaded)
	return nil
}

// Attach enables the reuseport selector for the configured reuseport group.
//
// On first attach, the program is attached to the socket group.
// On subsequent re-attach after Detach, the active config is restored
// without requiring the server to stop.
func (m *Module) Attach(ctx context.Context) error {
	_ = ctx

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.lifecycle.ValidateAttach(); err != nil {
		return err
	}

	if err := m.validateReadyLocked(); err != nil {
		return err
	}

	if err := ebpfmaps.SyncSockArray(m.bundle.SockMap, m.group.FDs()); err != nil {
		return fmt.Errorf("sync reuseport sockarray: %w", err)
	}

	if err := ebpfmaps.UpdateArrayValue(m.bundle.ConfigMap, 0, &bpfConfig{
		S11MessageType:      m.activeConfig.S11MessageType,
		S10MessageType:      m.activeConfig.S10MessageType,
		AllowKernelFallback: boolToUint8(m.activeConfig.AllowKernelFallback),
		S11PoolBase:         m.activeConfig.S11PoolBase,
		S11PoolSize:         m.activeConfig.S11PoolSize,
		S10PoolBase:         m.activeConfig.S10PoolBase,
		S10PoolSize:         m.activeConfig.S10PoolSize,
		FallbackPoolBase:    m.activeConfig.FallbackPoolBase,
		FallbackPoolSize:    m.activeConfig.FallbackPoolSize,
	}); err != nil {
		return fmt.Errorf("update active reuseport config: %w", err)
	}

	if !m.programBound {
		fd, err := m.group.FD(0)
		if err != nil {
			return fmt.Errorf("get reuseport group fd[0]: %w", err)
		}

		if err := attachProgram(fd, m.bundle.Selector); err != nil {
			return fmt.Errorf("attach reuseport selector: %w", err)
		}

		m.programBound = true
	}

	m.lifecycle.Transition(core.StateAttached)
	return nil
}

// Detach disables custom steering at runtime without stopping the server.
//
// For reuseport, Detach is implemented as a fallback-only mode:
// the selector remains attached, but its config is switched so that
// all packets fall back to the kernel default reuseport hashing path.
func (m *Module) Detach(ctx context.Context) error {
	_ = ctx

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.lifecycle.ValidateDetach(); err != nil {
		return err
	}

	if m.bundle == nil || m.bundle.ConfigMap == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}

	if err := ebpfmaps.UpdateArrayValue(m.bundle.ConfigMap, 0, &bpfConfig{
		S11MessageType:      m.disabledConfig.S11MessageType,
		S10MessageType:      m.disabledConfig.S10MessageType,
		AllowKernelFallback: boolToUint8(m.disabledConfig.AllowKernelFallback),
		S11PoolBase:         m.disabledConfig.S11PoolBase,
		S11PoolSize:         m.disabledConfig.S11PoolSize,
		S10PoolBase:         m.disabledConfig.S10PoolBase,
		S10PoolSize:         m.disabledConfig.S10PoolSize,
		FallbackPoolBase:    m.disabledConfig.FallbackPoolBase,
		FallbackPoolSize:    m.disabledConfig.FallbackPoolSize,
	}); err != nil {
		return fmt.Errorf("update disabled reuseport config: %w", err)
	}

	m.lifecycle.Transition(core.StateDetached)
	return nil
}

// Close releases all module resources.
//
// If the module is currently attached, Close first switches it into detached mode.
func (m *Module) Close(ctx context.Context) error {
	_ = ctx

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lifecycle.State() == core.StateClosed {
		return nil
	}

	var firstErr error

	if m.lifecycle.State() == core.StateAttached && m.bundle != nil && m.bundle.ConfigMap != nil {
		if err := ebpfmaps.UpdateArrayValue(m.bundle.ConfigMap, 0, &bpfConfig{
			S11MessageType:      m.disabledConfig.S11MessageType,
			S10MessageType:      m.disabledConfig.S10MessageType,
			AllowKernelFallback: boolToUint8(m.disabledConfig.AllowKernelFallback),
			S11PoolBase:         m.disabledConfig.S11PoolBase,
			S11PoolSize:         m.disabledConfig.S11PoolSize,
			S10PoolBase:         m.disabledConfig.S10PoolBase,
			S10PoolSize:         m.disabledConfig.S10PoolSize,
			FallbackPoolBase:    m.disabledConfig.FallbackPoolBase,
			FallbackPoolSize:    m.disabledConfig.FallbackPoolSize,
		}); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("disable reuseport selector before close: %w", err)
		}
	}

	if m.bundle != nil {
		if err := m.bundle.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close reuseport artifact bundle: %w", err)
		}
	}

	m.bundle = nil
	m.programBound = false
	m.lifecycle.Transition(core.StateClosed)

	return firstErr
}

func (m *Module) validateReadyLocked() error {
	if m.bundle == nil {
		return fmt.Errorf("reuseport artifact bundle is nil")
	}
	if m.bundle.Selector == nil {
		return fmt.Errorf("reuseport selector program is nil")
	}
	if m.bundle.SockMap == nil {
		return fmt.Errorf("reuseport sock_map is nil")
	}
	if m.bundle.ConfigMap == nil {
		return fmt.Errorf("reuseport config_map is nil")
	}
	if m.group == nil {
		return fmt.Errorf("reuseport group is nil")
	}

	return nil
}

func buildDisabledConfig(cfg Config) Config {
	return Config{
		S11MessageType:      cfg.S11MessageType,
		S10MessageType:      cfg.S10MessageType,
		S11PoolBase:         0,
		S11PoolSize:         0,
		S10PoolBase:         0,
		S10PoolSize:         0,
		FallbackPoolBase:    0,
		FallbackPoolSize:    0,
		AllowKernelFallback: true,
	}
}

func boolToUint8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}