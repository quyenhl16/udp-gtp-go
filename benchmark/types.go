package benchmark

import "time"

// Mode defines the benchmark interaction style.
type Mode string

const (
	// ModeFireAndForget sends UDP packets without waiting for a response.
	ModeFireAndForget Mode = "fire_and_forget"

	// ModeRequestResponse sends UDP packets and waits for a response.
	ModeRequestResponse Mode = "request_response"
)

// TrafficClass defines one traffic bucket in the generated mix.
type TrafficClass struct {
	Name        string
	MessageType uint8
	Weight      int
}

// Result contains the final benchmark output.
type Result struct {
	Target string
	Mode   Mode

	Workers int

	StartedAt time.Time
	EndedAt   time.Time
	Duration  time.Duration

	SentPackets     uint64
	ReceivedPackets uint64
	SentBytes       uint64
	ReceivedBytes   uint64

	WriteErrors uint64
	ReadErrors  uint64
	Timeouts    uint64

	PacketsPerSecond float64
	BytesPerSecond   float64

	Latency LatencySummary
}
