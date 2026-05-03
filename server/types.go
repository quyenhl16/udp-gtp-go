package server

import (
	"context"
	"net"
	"time"
)

// Packet represents a received UDP datagram together with runtime metadata.
type Packet struct {
	SocketIndex int
	Data        []byte
	RemoteAddr  *net.UDPAddr
	LocalAddr   net.Addr
	ReceivedAt  time.Time
}

// ResponseWriter writes packets back through the same socket that received them.
type ResponseWriter interface {
	Write(payload []byte, addr *net.UDPAddr) (int, error)
}

// Handler processes received packets.
type Handler interface {
	HandlePacket(ctx context.Context, pkt Packet, w ResponseWriter) error
}

// HandlerFunc converts a function into a Handler.
type HandlerFunc func(ctx context.Context, pkt Packet, w ResponseWriter) error

// HandlePacket implements Handler.
func (f HandlerFunc) HandlePacket(ctx context.Context, pkt Packet, w ResponseWriter) error {
	return f(ctx, pkt, w)
}

// Observer receives runtime events from the server.
// This interface is intentionally small so metrics and tracing can be added later.
type Observer interface {
	OnStart(addr net.Addr, socketCount int)
	OnStop()
	OnPacketReceived(pkt Packet)
	OnReadError(socketIndex int, err error)
	OnHandleError(pkt Packet, err error)
	OnWriteError(pkt Packet, err error)
}

// NopObserver is the default no-op runtime observer.
type NopObserver struct{}

// OnStart implements Observer.
func (NopObserver) OnStart(addr net.Addr, socketCount int) {}

// OnStop implements Observer.
func (NopObserver) OnStop() {}

// OnPacketReceived implements Observer.
func (NopObserver) OnPacketReceived(pkt Packet) {}

// OnReadError implements Observer.
func (NopObserver) OnReadError(socketIndex int, err error) {}

// OnHandleError implements Observer.
func (NopObserver) OnHandleError(pkt Packet, err error) {}

// OnWriteError implements Observer.
func (NopObserver) OnWriteError(pkt Packet, err error) {}