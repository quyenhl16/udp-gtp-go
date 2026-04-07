package core

import (
	"fmt"
	"sync"
)

// Registry stores loaded eBPF modules by logical name.
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// NewRegistry creates an empty Registry.
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
	if _, exists := r.modules[name]; exists {
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

// Close closes all registered modules.
func (r *Registry) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	for _, module := range r.modules {
		if module == nil {
			continue
		}
		if err := module.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	r.modules = make(map[string]Module)
	return firstErr
}