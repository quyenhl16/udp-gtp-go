package metrics

import (
	"net"

	"github.com/quyenhl16/udp-gtp-go/gtpv2"
	"github.com/quyenhl16/udp-gtp-go/server"
)

// Observer collects in-memory counters from server runtime events.
type Observer struct {
	counters *Counters
}

// NewObserver creates a metrics observer with its own counter set.
func NewObserver() *Observer {
	return &Observer{
		counters: NewCounters(),
	}
}

// NewObserverWithCounters creates a metrics observer using the provided counter set.
func NewObserverWithCounters(counters *Counters) *Observer {
	if counters == nil {
		counters = NewCounters()
	}

	return &Observer{
		counters: counters,
	}
}

// Counters returns the underlying counter set.
func (o *Observer) Counters() *Counters {
	if o == nil {
		return nil
	}
	return o.counters
}

// Snapshot returns a point-in-time metrics snapshot.
func (o *Observer) Snapshot() Snapshot {
	if o == nil || o.counters == nil {
		return Snapshot{
			PacketsBySocket:      map[int]uint64{},
			BytesBySocket:        map[int]uint64{},
			PacketsByMessageType: map[uint8]uint64{},
		}
	}

	return o.counters.Snapshot()
}

// OnStart implements server.Observer.
func (o *Observer) OnStart(addr net.Addr, socketCount int) {}

// OnStop implements server.Observer.
func (o *Observer) OnStop() {}

// OnPacketReceived implements server.Observer.
func (o *Observer) OnPacketReceived(pkt server.Packet) {
	if o == nil || o.counters == nil {
		return
	}

	o.counters.IncPackets(1)
	o.counters.IncBytes(uint64(len(pkt.Data)))
	o.counters.IncPacketsBySocket(pkt.SocketIndex, 1)
	o.counters.IncBytesBySocket(pkt.SocketIndex, uint64(len(pkt.Data)))

	msgType, err := gtpv2.MessageType(pkt.Data)
	if err == nil {
		o.counters.IncPacketsByMessageType(msgType, 1)
	}
}

// OnReadError implements server.Observer.
func (o *Observer) OnReadError(socketIndex int, err error) {
	if o == nil || o.counters == nil {
		return
	}

	o.counters.IncReadErrors(1)
}

// OnHandleError implements server.Observer.
func (o *Observer) OnHandleError(pkt server.Packet, err error) {
	if o == nil || o.counters == nil {
		return
	}

	o.counters.IncHandleErrors(1)
}

// OnWriteError implements server.Observer.
func (o *Observer) OnWriteError(pkt server.Packet, err error) {
	if o == nil || o.counters == nil {
		return
	}

	o.counters.IncWriteErrors(1)
}