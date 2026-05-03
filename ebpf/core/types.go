package core

import "context"

// State represents the lifecycle state of an eBPF module.
type State string

const (
	// StateNew indicates that the module has been created but not loaded.
	StateNew State = "new"

	// StateLoaded indicates that the eBPF objects are loaded into the kernel,
	// but the module is not attached yet.
	StateLoaded State = "loaded"

	// StateAttached indicates that the module is currently attached to its hook.
	StateAttached State = "attached"

	// StateDetached indicates that the module was previously attached and is now detached.
	StateDetached State = "detached"

	// StateClosed indicates that the module has been fully closed.
	StateClosed State = "closed"
)

// Module is the common lifecycle contract implemented by all eBPF runtime modules.
type Module interface {
	// Name returns the logical module name.
	Name() string

	// Load loads all eBPF objects needed by the module.
	Load(ctx context.Context) error

	// Attach attaches the module to its runtime hook.
	Attach(ctx context.Context) error

	// Detach detaches the module from its runtime hook without requiring
	// the server to stop.
	Detach(ctx context.Context) error

	// Close releases all module resources.
	Close(ctx context.Context) error

	// State returns the current lifecycle state.
	State() State

	// IsEnabled reports whether the module is currently attached.
	IsEnabled() bool
}