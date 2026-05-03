package core

import "errors"

var (
	// ErrNilCollection indicates that the collection is nil.
	ErrNilCollection = errors.New("ebpf collection is nil")

	// ErrProgramNotFound indicates that the requested program was not found.
	ErrProgramNotFound = errors.New("ebpf program not found")

	// ErrMapNotFound indicates that the requested map was not found.
	ErrMapNotFound = errors.New("ebpf map not found")

	// ErrModuleAlreadyExists indicates that a module with the same name
	// is already registered.
	ErrModuleAlreadyExists = errors.New("ebpf module already exists")

	// ErrModuleNotFound indicates that the requested module does not exist.
	ErrModuleNotFound = errors.New("ebpf module not found")

	// ErrInvalidStateTransition indicates that a lifecycle operation
	// is not valid for the current module state.
	ErrInvalidStateTransition = errors.New("invalid module state transition")

	// ErrModuleNotLoaded indicates that the module must be loaded first.
	ErrModuleNotLoaded = errors.New("ebpf module is not loaded")

	// ErrModuleNotAttached indicates that the module is not attached.
	ErrModuleNotAttached = errors.New("ebpf module is not attached")

	// ErrModuleAlreadyAttached indicates that the module is already attached.
	ErrModuleAlreadyAttached = errors.New("ebpf module is already attached")

	// ErrModuleClosed indicates that the module is already closed.
	ErrModuleClosed = errors.New("ebpf module is closed")
)