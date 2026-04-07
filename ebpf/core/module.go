package core

// Module is the common contract implemented by all eBPF runtime modules.
type Module interface {
	Name() string
	Load() error
	Collection() *Collection
	Close() error
}