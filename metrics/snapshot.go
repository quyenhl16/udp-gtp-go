package metrics

import "time"

// LatencySnapshot contains packet handler-completion latency percentiles. With
// benchmark timestamp instrumentation enabled, latency begins at client send;
// otherwise it begins when the server reads the datagram.
type LatencySnapshot struct {
	Count uint64
	P50   time.Duration
	P95   time.Duration
	P99   time.Duration
}

// Snapshot contains a point-in-time copy of all collected metrics.
type Snapshot struct {
	PacketsTotal          uint64
	ProcessedPacketsTotal uint64
	BytesTotal            uint64

	ReadErrorsTotal      uint64
	HandleErrorsTotal    uint64
	WriteErrorsTotal     uint64
	ReceiveOverflowTotal uint64

	ProcessingLatency LatencySnapshot

	PacketsBySocket map[int]uint64
	BytesBySocket   map[int]uint64

	PacketsByMessageType map[uint8]uint64
}
