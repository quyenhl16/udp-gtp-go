package metrics

import (
	"math"
	"math/bits"
	"sync/atomic"
	"time"
)

// Sixteen sub-buckets per power of two bound memory and recording overhead
// while keeping percentile estimates within roughly 6.25%.
const (
	latencySubBuckets = 16
	latencyBuckets    = 64 * latencySubBuckets
)

type latencyHistogram struct {
	count   atomic.Uint64
	buckets [latencyBuckets]atomic.Uint64
}

func (h *latencyHistogram) Observe(value time.Duration) {
	if value < 0 {
		value = 0
	}
	index := latencyBucketIndex(uint64(value))
	h.buckets[index].Add(1)
	h.count.Add(1)
}

func (h *latencyHistogram) Snapshot() LatencySnapshot {
	count := h.count.Load()
	if count == 0 {
		return LatencySnapshot{}
	}

	counts := make([]uint64, latencyBuckets)
	for i := range h.buckets {
		counts[i] = h.buckets[i].Load()
	}

	return LatencySnapshot{
		Count: count,
		P50:   latencyPercentile(counts, count, 50),
		P95:   latencyPercentile(counts, count, 95),
		P99:   latencyPercentile(counts, count, 99),
	}
}

func latencyBucketIndex(nanoseconds uint64) int {
	if nanoseconds == 0 {
		return 0
	}

	exponent := bits.Len64(nanoseconds) - 1
	base := uint64(1) << exponent
	var subBucket uint64
	if exponent < 4 {
		subBucket = nanoseconds - base
	} else {
		subBucket = (nanoseconds - base) / (base / latencySubBuckets)
	}
	if subBucket >= latencySubBuckets {
		subBucket = latencySubBuckets - 1
	}

	index := exponent*latencySubBuckets + int(subBucket)
	if index >= latencyBuckets {
		return latencyBuckets - 1
	}
	return index
}

func latencyPercentile(counts []uint64, count uint64, percentile uint64) time.Duration {
	target := (count*percentile + 99) / 100
	var cumulative uint64
	for index, bucketCount := range counts {
		cumulative += bucketCount
		if cumulative >= target {
			return latencyBucketUpperBound(index)
		}
	}
	return latencyBucketUpperBound(len(counts) - 1)
}

func latencyBucketUpperBound(index int) time.Duration {
	exponent := index / latencySubBuckets
	subBucket := index % latencySubBuckets
	base := uint64(1) << exponent
	var upper uint64
	if exponent < 4 {
		upper = base + uint64(subBucket)
	} else {
		upper = base + uint64(subBucket+1)*(base/latencySubBuckets) - 1
	}
	if upper > math.MaxInt64 {
		upper = math.MaxInt64
	}
	return time.Duration(upper)
}
