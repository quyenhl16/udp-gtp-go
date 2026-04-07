package reuseport

// Config defines the runtime configuration pushed into the reuseport config map.
type Config struct {
	S11MessageType      uint8
	S10MessageType      uint8
	S11PoolBase         uint32
	S11PoolSize         uint32
	S10PoolBase         uint32
	S10PoolSize         uint32
	FallbackPoolBase    uint32
	FallbackPoolSize    uint32
	AllowKernelFallback bool
}

// bpfConfig must match the C struct layout exactly.
type bpfConfig struct {
	S11MessageType      uint8
	S10MessageType      uint8
	AllowKernelFallback uint8
	_                   uint8

	S11PoolBase      uint32
	S11PoolSize      uint32
	S10PoolBase      uint32
	S10PoolSize      uint32
	FallbackPoolBase uint32
	FallbackPoolSize uint32
}