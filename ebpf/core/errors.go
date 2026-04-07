package core

import "errors"

var (
	// ErrNilCollection indicates that the collection is nil.
	ErrNilCollection = errors.New("ebpf collection is nil")

	// ErrProgramNotFound indicates that the requested program was not found.
	ErrProgramNotFound = errors.New("ebpf program not found")

	// ErrMapNotFound indicates that the requested map was not found.
	ErrMapNotFound = errors.New("ebpf map not found")

	// ErrModuleAlreadyExists indicates that a module name is already registered.
	ErrModuleAlreadyExists = errors.New("ebpf module already exists")

	// ErrModuleNotFound indicates that the requested module does not exist.
	ErrModuleNotFound = errors.New("ebpf module not found")
)