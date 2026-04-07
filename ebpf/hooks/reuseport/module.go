package reuseport

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
	artifact "github.com/quyenhl16/udp-gtp-go/ebpf/artifacts/reuseport"
	"github.com/quyenhl16/udp-gtp-go/ebpf/core"
	ebpfmaps "github.com/quyenhl16/udp-gtp-go/ebpf/maps"
	udpgroup "github.com/quyenhl16/udp-gtp-go/reuseport"
)

// Module is the runtime adapter for the reuseport selector.
type Module struct {
	bundle     *artifact.Bundle
	collection *core.Collection
}

// New creates an unloaded reuseport module.
func New() *Module {
	return &Module{}
}

// Name returns the logical module name.
func (m *Module) Name() string {
	return "reuseport"
}

// Load loads the generated reuseport object and builds the runtime collection.
func (m *Module) Load() error {
	bundle, err := artifact.Load(nil)
	if err != nil {
		return err
	}

	coll := core.NewCollection()
	coll.AddProgram("select_reuseport", bundle.Selector)
	coll.AddMap("sock_map", bundle.SockMap)
	coll.AddMap("config_map", bundle.ConfigMap)

	m.bundle = bundle
	m.collection = coll
	return nil
}

// Collection returns the module collection.
func (m *Module) Collection() *core.Collection {
	return m.collection
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
	if m == nil || m.collection == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}

	configMap, err := m.collection.Map("config_map")
	if err != nil {
		return err
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

	return ebpfmaps.UpdateArrayValue(configMap, key, &value)
}

// SyncSockArray writes reuseport group sockets into sock_map.
func (m *Module) SyncSockArray(group *udpgroup.Group) error {
	if m == nil || m.collection == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}
	if group == nil {
		return fmt.Errorf("reuseport group is nil")
	}

	sockMap, err := m.collection.Map("sock_map")
	if err != nil {
		return err
	}

	return ebpfmaps.SyncSockArray(sockMap, group.FDs())
}

// Attach binds the selector program to the reuseport socket group.
func (m *Module) Attach(group *udpgroup.Group) error {
	if m == nil || m.collection == nil {
		return fmt.Errorf("reuseport module is not loaded")
	}
	if group == nil {
		return fmt.Errorf("reuseport group is nil")
	}

	prog, err := m.collection.Program("select_reuseport")
	if err != nil {
		return err
	}

	fd, err := group.FD(0)
	if err != nil {
		return fmt.Errorf("get reuseport group fd[0]: %w", err)
	}

	return attachProgram(fd, prog)
}

func boolToUint8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

// Program returns the underlying selector program when needed by upper layers.
func (m *Module) Program() (*ciliumebpf.Program, error) {
	if m == nil || m.collection == nil {
		return nil, fmt.Errorf("reuseport module is not loaded")
	}
	return m.collection.Program("select_reuseport")
}