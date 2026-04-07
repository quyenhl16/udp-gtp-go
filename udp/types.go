package udp

import (
	"context"
	"net"
	"time"
)

// Packet represents a single UDP datagram.
type Packet struct {
	Data       []byte
	RemoteAddr net.Addr
	LocalAddr  net.Addr
	ReceivedAt time.Time
}

// Reader defines a minimal UDP packet reader.
type Reader interface {
	ReadPacket(ctx context.Context, buf []byte) (Packet, error)
}

// Writer defines a minimal UDP packet writer.
type Writer interface {
	WritePacket(ctx context.Context, payload []byte, addr net.Addr) (int, error)
}

// Conn defines the minimal UDP connection contract used by upper layers.
type Conn interface {
	Reader
	Writer
	Close() error
	LocalAddr() net.Addr
	RawConn() *net.UDPConn
}