package benchmark

import (
	"sort"
	"time"
)

// LatencySummary contains basic latency percentiles.
type LatencySummary struct {
	Count int

	Min time.Duration
	Max time.Duration
	Avg time.Duration

	P50 time.Duration
	P95 time.Duration
	P99 time.Duration
}

func summarizeLatencies(values []time.Duration) LatencySummary {
	if len(values) == 0 {
		return LatencySummary{}
	}

	sorted := make([]time.Duration, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	var total time.Duration
	for _, v := range sorted {
		total += v
	}

	return LatencySummary{
		Count: len(sorted),
		Min:   sorted[0],
		Max:   sorted[len(sorted)-1],
		Avg:   total / time.Duration(len(sorted)),
		P50:   percentile(sorted, 50),
		P95:   percentile(sorted, 95),
		P99:   percentile(sorted, 99),
	}
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}

	index := (len(sorted) - 1) * p / 100
	return sorted[index]
}
