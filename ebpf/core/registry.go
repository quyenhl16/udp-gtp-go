package core

import (
	"context"
	"fmt"
	"sync"
)

// Registry stores runtime eBPF modules by name.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry creates an empty module registry.
func NewRegistry() *Registry {
	return &Registry{
		modules: make(map[string]Module),
	}
}

// Register adds a module to the registry.
func (r *Registry) Register(module Module) error {
	if r == nil {
		return fmt.Errorf("registry is nil")
	}
	if module == nil {
		return fmt.Errorf("module is nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := module.Name()
	if _, ok := r.modules[name]; ok {
		return fmt.Errorf("%w: %s", ErrModuleAlreadyExists, name)
	}

	r.modules[name] = module
	return nil
}

// Module returns a module by name.
func (r *Registry) Module(name string) (Module, error) {
	if r == nil {
		return nil, fmt.Errorf("registry is nil")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	module, ok := r.modules[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrModuleNotFound, name)
	}

	return module, nil
}

// Enable loads and attaches a module.
func (r *Registry) Enable(ctx context.Context, name string) error {
	module, err := r.Module(name)
	if err != nil {
		return err
	}

	if module.State() == StateNew {
		if err := module.Load(ctx); err != nil {
			return err
		}
	}

	if module.State() != StateAttached {
		if err := module.Attach(ctx); err != nil {
			return err
		}
	}

	return nil
}

// Disable detaches a module without closing it.
func (r *Registry) Disable(ctx context.Context, name string) error {
	module, err := r.Module(name)
	if err != nil {
		return err
	}

	if module.State() == StateAttached {
		return module.Detach(ctx)
	}

	return nil
}

// CloseAll closes all modules.
func (r *Registry) CloseAll(ctx context.Context) error {
	if r == nil {
		return nil
	}

	r.mu.RLock()
	modules := make([]Module, 0, len(r.modules))
	for _, module := range r.modules {
		modules = append(modules, module)
	}
	r.mu.RUnlock()

	var firstErr error
	for _, module := range modules {
		if module == nil {
			continue
		}
		if err := module.Close(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}