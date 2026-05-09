package server

import "net"

// MultiObserver fans out runtime events to multiple observers.
type MultiObserver struct {
	observers []Observer
}

// NewMultiObserver creates a composite observer from the provided observers.
//
// Nil observers are ignored.
// If all observers are nil, the result behaves like a no-op observer.
func NewMultiObserver(observers ...Observer) Observer {
	filtered := make([]Observer, 0, len(observers))
	for _, observer := range observers {
		if observer == nil {
			continue
		}
		filtered = append(filtered, observer)
	}

	if len(filtered) == 0 {
		return NopObserver{}
	}

	if len(filtered) == 1 {
		return filtered[0]
	}

	return MultiObserver{
		observers: filtered,
	}
}

// OnStart implements Observer.
func (m MultiObserver) OnStart(addr net.Addr, socketCount int) {
	for _, observer := range m.observers {
		observer.OnStart(addr, socketCount)
	}
}

// OnStop implements Observer.
func (m MultiObserver) OnStop() {
	for _, observer := range m.observers {
		observer.OnStop()
	}
}

// OnPacketReceived implements Observer.
func (m MultiObserver) OnPacketReceived(pkt Packet) {
	for _, observer := range m.observers {
		observer.OnPacketReceived(pkt)
	}
}

// OnReadError implements Observer.
func (m MultiObserver) OnReadError(socketIndex int, err error) {
	for _, observer := range m.observers {
		observer.OnReadError(socketIndex, err)
	}
}

// OnHandleError implements Observer.
func (m MultiObserver) OnHandleError(pkt Packet, err error) {
	for _, observer := range m.observers {
		observer.OnHandleError(pkt, err)
	}
}

// OnWriteError implements Observer.
func (m MultiObserver) OnWriteError(pkt Packet, err error) {
	for _, observer := range m.observers {
		observer.OnWriteError(pkt, err)
	}
}