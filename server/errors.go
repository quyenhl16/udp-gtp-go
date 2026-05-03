package server

import "errors"

var (
	// ErrNilConfig indicates that the provided config is nil.
	ErrNilConfig = errors.New("server config is nil")

	// ErrServerStarted indicates that the server is already running.
	ErrServerStarted = errors.New("server already started")

	// ErrServerNotStarted indicates that the server is not running.
	ErrServerNotStarted = errors.New("server not started")

	// ErrNilHandler indicates that the configured handler is nil.
	ErrNilHandler = errors.New("server handler is nil")

	// ErrUnknownMode indicates that the runtime mode is unknown.
	ErrUnknownMode = errors.New("unknown server mode")

	// ErrReuseportEBPFRequiresReusePort indicates that the reuseport eBPF
	// module cannot run when reuseport mode is disabled.
	ErrReuseportEBPFRequiresReusePort = errors.New("reuseport ebpf requires reuseport mode")
)