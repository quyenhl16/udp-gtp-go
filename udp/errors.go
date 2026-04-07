package udp

import "errors"

var (
	// ErrNilUDPConn indicates that the underlying UDP connection is nil.
	ErrNilUDPConn = errors.New("udp connection is nil")

	// ErrNilRemoteAddr indicates that the destination address is nil.
	ErrNilRemoteAddr = errors.New("remote address is nil")
)