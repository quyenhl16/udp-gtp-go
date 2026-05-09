package metrics

// Snapshot contains a point-in-time copy of all collected metrics.
type Snapshot struct {
	PacketsTotal uint64
	BytesTotal   uint64

	ReadErrorsTotal   uint64
	HandleErrorsTotal uint64
	WriteErrorsTotal  uint64

	PacketsBySocket map[int]uint64
	BytesBySocket   map[int]uint64

	PacketsByMessageType map[uint8]uint64
}