package benchmark

import (
	"fmt"
	"time"
)

// PacketsPerSecond returns a packet rate over the supplied measurement window.
func PacketsPerSecond(packets uint64, duration time.Duration) float64 {
	if duration <= 0 {
		return 0
	}
	return float64(packets) / duration.Seconds()
}

// DeliveryRatio returns the percentage of sent packets observed by the server.
func DeliveryRatio(sent, received uint64) float64 {
	if sent == 0 {
		return 0
	}
	return float64(received) / float64(sent) * 100
}

// InferredDrops returns packets sent by the client but not observed by the
// server. It saturates at zero because asynchronous snapshots can briefly make
// received exceed sent.
func InferredDrops(sent, received uint64) uint64 {
	if received >= sent {
		return 0
	}
	return sent - received
}

// FormatLatency formats a percentile, using n/a when there are no samples.
func FormatLatency(count uint64, value time.Duration) string {
	if count == 0 {
		return "n/a"
	}
	return value.String()
}

// FormatResult formats a benchmark result into a readable multi-line report.
func FormatResult(r Result) string {
	return fmt.Sprintf(
		"target=%s\nmode=%s\nworkers=%d\nduration=%s\nsent_packets=%d\nreceived_packets=%d\nsent_bytes=%d\nreceived_bytes=%d\nwrite_errors=%d\nread_errors=%d\ntimeouts=%d\npps=%.2f\nbytes_per_sec=%.2f\nlatency_count=%d\nlatency_min=%s\nlatency_avg=%s\nlatency_p50=%s\nlatency_p95=%s\nlatency_p99=%s\nlatency_max=%s\n",
		r.Target,
		r.Mode,
		r.Workers,
		r.Duration,
		r.SentPackets,
		r.ReceivedPackets,
		r.SentBytes,
		r.ReceivedBytes,
		r.WriteErrors,
		r.ReadErrors,
		r.Timeouts,
		r.PacketsPerSecond,
		r.BytesPerSecond,
		r.Latency.Count,
		r.Latency.Min,
		r.Latency.Avg,
		r.Latency.P50,
		r.Latency.P95,
		r.Latency.P99,
		r.Latency.Max,
	)
}
