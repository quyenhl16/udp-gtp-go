package metrics

import (
	"testing"
	"time"
)

func TestLatencyHistogramPercentiles(t *testing.T) {
	var histogram latencyHistogram
	for i := 1; i <= 100; i++ {
		histogram.Observe(time.Duration(i) * time.Microsecond)
	}

	snapshot := histogram.Snapshot()
	if snapshot.Count != 100 {
		t.Fatalf("Count = %d, want 100", snapshot.Count)
	}
	assertApproxDuration(t, "p50", snapshot.P50, 50*time.Microsecond)
	assertApproxDuration(t, "p95", snapshot.P95, 95*time.Microsecond)
	assertApproxDuration(t, "p99", snapshot.P99, 99*time.Microsecond)
}

func assertApproxDuration(t *testing.T, name string, got, want time.Duration) {
	t.Helper()
	const tolerance = 7 * time.Microsecond
	if got < want-tolerance || got > want+tolerance {
		t.Fatalf("%s = %s, want %s +/- %s", name, got, want, tolerance)
	}
}
