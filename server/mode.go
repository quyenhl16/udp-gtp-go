package server

// Mode represents the server transport mode.
type Mode string

const (
	// ModeSingle uses a single plain UDP socket.
	ModeSingle Mode = "single"

	// ModeReusePort uses a UDP SO_REUSEPORT socket group.
	ModeReusePort Mode = "reuseport"
)