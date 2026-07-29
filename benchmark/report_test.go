package benchmark

import (
	"testing"
	"time"
)

func TestSummaryCalculations(t *testing.T) {
	if got := PacketsPerSecond(2500, time.Second); got != 2500 {
		t.Fatalf("PacketsPerSecond() = %v, want 2500", got)
	}
	if got := DeliveryRatio(100, 75); got != 75 {
		t.Fatalf("DeliveryRatio() = %v, want 75", got)
	}
	if got := InferredDrops(100, 75); got != 25 {
		t.Fatalf("InferredDrops() = %d, want 25", got)
	}
	if got := InferredDrops(75, 100); got != 0 {
		t.Fatalf("InferredDrops() with received > sent = %d, want 0", got)
	}
}

func TestFormatLatencyWithoutSamples(t *testing.T) {
	if got := FormatLatency(0, 0); got != "n/a" {
		t.Fatalf("FormatLatency() = %q, want n/a", got)
	}
}

func TestProcessCPUUsageUsesProcessedThroughput(t *testing.T) {
	startedAt := time.Unix(100, 0)
	metrics := ProcessCPUUsage(
		ProcessCPUSnapshot{wallTime: startedAt, cpuTime: time.Second},
		ProcessCPUSnapshot{wallTime: startedAt.Add(2 * time.Second), cpuTime: 2 * time.Second},
		10_000,
	)

	if metrics.AverageUtilizationPercent != 50 {
		t.Fatalf("AverageUtilizationPercent = %v, want 50", metrics.AverageUtilizationPercent)
	}
	if metrics.CPUPerProcessedKpps != 5 {
		t.Fatalf("CPUPerProcessedKpps = %v, want 5", metrics.CPUPerProcessedKpps)
	}
}
