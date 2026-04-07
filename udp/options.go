package udp

import "time"

// Options defines low-level UDP socket options.
type Options struct {
	Network         string
	Host            string
	Port            int
	ReadBufferBytes int
	WriteBufferBytes int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// DefaultOptions returns a sensible default UDP configuration.
func DefaultOptions() Options {
	return Options{
		Network:          "udp",
		Host:             "0.0.0.0",
		Port:             0,
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
	if o.ReadBufferBytes < 0 {
		o.ReadBufferBytes = 0
	}
	if o.WriteBufferBytes < 0 {
		o.WriteBufferBytes = 0
	}
}