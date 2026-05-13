package benchmark

import "fmt"

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
