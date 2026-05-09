package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Counters stores runtime counters in memory using atomic primitives.
type Counters struct {
	packetsTotal atomic.Uint64
	bytesTotal   atomic.Uint64

	readErrorsTotal   atomic.Uint64
	handleErrorsTotal atomic.Uint64
	writeErrorsTotal  atomic.Uint64

	packetsBySocket sync.Map // map[int]*atomic.Uint64
	bytesBySocket   sync.Map // map[int]*atomic.Uint64

	packetsByMessageType sync.Map // map[uint8]*atomic.Uint64
}

// NewCounters creates an empty in-memory counter set.
func NewCounters() *Counters {
	return &Counters{}
}

// IncPackets increments the total packet counter.
func (c *Counters) IncPackets(n uint64) {
	c.packetsTotal.Add(n)
}

// IncBytes increments the total byte counter.
func (c *Counters) IncBytes(n uint64) {
	c.bytesTotal.Add(n)
}

// IncReadErrors increments the total read error counter.
func (c *Counters) IncReadErrors(n uint64) {
	c.readErrorsTotal.Add(n)
}

// IncHandleErrors increments the total handler error counter.
func (c *Counters) IncHandleErrors(n uint64) {
	c.handleErrorsTotal.Add(n)
}

// IncWriteErrors increments the total write error counter.
func (c *Counters) IncWriteErrors(n uint64) {
	c.writeErrorsTotal.Add(n)
}

// IncPacketsBySocket increments the packet counter for one socket.
func (c *Counters) IncPacketsBySocket(socketIndex int, n uint64) {
	counter := loadOrCreateIntCounter(&c.packetsBySocket, socketIndex)
	counter.Add(n)
}

// IncBytesBySocket increments the byte counter for one socket.
func (c *Counters) IncBytesBySocket(socketIndex int, n uint64) {
	counter := loadOrCreateIntCounter(&c.bytesBySocket, socketIndex)
	counter.Add(n)
}

// IncPacketsByMessageType increments the packet counter for one message type.
func (c *Counters) IncPacketsByMessageType(messageType uint8, n uint64) {
	counter := loadOrCreateUint8Counter(&c.packetsByMessageType, messageType)
	counter.Add(n)
}

// Snapshot returns a consistent copy of the current counters.
func (c *Counters) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{
			PacketsBySocket:      map[int]uint64{},
			BytesBySocket:        map[int]uint64{},
			PacketsByMessageType: map[uint8]uint64{},
		}
	}

	out := Snapshot{
		PacketsTotal: c.packetsTotal.Load(),
		BytesTotal:   c.bytesTotal.Load(),

		ReadErrorsTotal:   c.readErrorsTotal.Load(),
		HandleErrorsTotal: c.handleErrorsTotal.Load(),
		WriteErrorsTotal:  c.writeErrorsTotal.Load(),

		PacketsBySocket:      map[int]uint64{},
		BytesBySocket:        map[int]uint64{},
		PacketsByMessageType: map[uint8]uint64{},
	}

	c.packetsBySocket.Range(func(key, value any) bool {
		k, ok1 := key.(int)
		v, ok2 := value.(*atomic.Uint64)
		if ok1 && ok2 && v != nil {
			out.PacketsBySocket[k] = v.Load()
		}
		return true
	})

	c.bytesBySocket.Range(func(key, value any) bool {
		k, ok1 := key.(int)
		v, ok2 := value.(*atomic.Uint64)
		if ok1 && ok2 && v != nil {
			out.BytesBySocket[k] = v.Load()
		}
		return true
	})

	c.packetsByMessageType.Range(func(key, value any) bool {
		k, ok1 := key.(uint8)
		v, ok2 := value.(*atomic.Uint64)
		if ok1 && ok2 && v != nil {
			out.PacketsByMessageType[k] = v.Load()
		}
		return true
	})

	return out
}

// SortedSocketKeys returns the socket indexes found in the snapshot in ascending order.
func SortedSocketKeys(s Snapshot) []int {
	keys := make([]int, 0, len(s.PacketsBySocket))
	for k := range s.PacketsBySocket {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// SortedMessageTypeKeys returns the message types found in the snapshot in ascending order.
func SortedMessageTypeKeys(s Snapshot) []uint8 {
	keys := make([]uint8, 0, len(s.PacketsByMessageType))
	for k := range s.PacketsByMessageType {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func loadOrCreateIntCounter(m *sync.Map, key int) *atomic.Uint64 {
	if m == nil {
		return &atomic.Uint64{}
	}

	if value, ok := m.Load(key); ok {
		if counter, ok := value.(*atomic.Uint64); ok && counter != nil {
			return counter
		}
	}

	counter := &atomic.Uint64{}
	actual, _ := m.LoadOrStore(key, counter)

	if resolved, ok := actual.(*atomic.Uint64); ok && resolved != nil {
		return resolved
	}

	return counter
}

func loadOrCreateUint8Counter(m *sync.Map, key uint8) *atomic.Uint64 {
	if m == nil {
		return &atomic.Uint64{}
	}

	if value, ok := m.Load(key); ok {
		if counter, ok := value.(*atomic.Uint64); ok && counter != nil {
			return counter
		}
	}

	counter := &atomic.Uint64{}
	actual, _ := m.LoadOrStore(key, counter)

	if resolved, ok := actual.(*atomic.Uint64); ok && resolved != nil {
		return resolved
	}

	return counter
}