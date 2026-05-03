package core

import (
	"fmt"
	"sync"
)

// Lifecycle provides reusable state management for modules.
type Lifecycle struct {
	mu    sync.RWMutex
	state State
}

// NewLifecycle creates a new lifecycle initialized to StateNew.
func NewLifecycle() Lifecycle {
	return Lifecycle{
		state: StateNew,
	}
}

// State returns the current lifecycle state.
func (l *Lifecycle) State() State {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return l.state
}

// IsEnabled reports whether the module is currently attached.
func (l *Lifecycle) IsEnabled() bool {
	return l.State() == StateAttached
}

// Transition updates the lifecycle state.
func (l *Lifecycle) Transition(next State) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.state = next
}

// ValidateLoad checks whether Load is allowed.
func (l *Lifecycle) ValidateLoad() error {
	switch l.State() {
	case StateNew:
		return nil
	case StateLoaded, StateDetached, StateAttached:
		return nil
	case StateClosed:
		return ErrModuleClosed
	default:
		return fmt.Errorf("%w: load from %s", ErrInvalidStateTransition, l.State())
	}
}

// ValidateAttach checks whether Attach is allowed.
func (l *Lifecycle) ValidateAttach() error {
	switch l.State() {
	case StateLoaded, StateDetached:
		return nil
	case StateAttached:
		return ErrModuleAlreadyAttached
	case StateNew:
		return ErrModuleNotLoaded
	case StateClosed:
		return ErrModuleClosed
	default:
		return fmt.Errorf("%w: attach from %s", ErrInvalidStateTransition, l.State())
	}
}

// ValidateDetach checks whether Detach is allowed.
func (l *Lifecycle) ValidateDetach() error {
	switch l.State() {
	case StateAttached:
		return nil
	case StateLoaded, StateDetached:
		return ErrModuleNotAttached
	case StateNew:
		return ErrModuleNotLoaded
	case StateClosed:
		return ErrModuleClosed
	default:
		return fmt.Errorf("%w: detach from %s", ErrInvalidStateTransition, l.State())
	}
}

// ValidateClose checks whether Close is allowed.
func (l *Lifecycle) ValidateClose() error {
	if l.State() == StateClosed {
		return ErrModuleClosed
	}
	return nil
}