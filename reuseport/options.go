package reuseport

// Options defines the configuration for a UDP reuseport socket group.
type Options struct {
	Network          string
	Host             string
	Port             int
	SocketCount      int
	ReadBufferBytes  int
	WriteBufferBytes int
}

// DefaultOptions returns a sensible default reuseport configuration.
func DefaultOptions() Options {
	return Options{
		Network:          "udp",
		Host:             "0.0.0.0",
		Port:             0,
		SocketCount:      1,
		ReadBufferBytes:  4 * 1024 * 1024,
		WriteBufferBytes: 4 * 1024 * 1024,
	}
}

// Normalize applies default values for missing fields.
func (o *Options) Normalize() {
	if o.Network == "" {
		o.Network = "udp"
	}
	if o.Host == "" {
		o.Host = "0.0.0.0"
	}
	if o.SocketCount <= 0 {
		o.SocketCount = 1
	}
	if o.ReadBufferBytes < 0 {
		o.ReadBufferBytes = 0
	}
	if o.WriteBufferBytes < 0 {
		o.WriteBufferBytes = 0
	}
}