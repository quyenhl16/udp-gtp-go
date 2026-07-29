package benchmark

import (
	"errors"
	"fmt"
	"math"
	"time"
)

// ErrCPUUsageUnavailable indicates that process CPU sampling is not supported.
var ErrCPUUsageUnavailable = errors.New("process cpu usage unavailable")

// ProcessCPUSnapshot captures cumulative process CPU time at a wall-clock point.
type ProcessCPUSnapshot struct {
	wallTime time.Time
	cpuTime  time.Duration
}

// ProcessCPUMetrics describes process CPU usage over a benchmark interval.
type ProcessCPUMetrics struct {
	Available                 bool
	WallDuration              time.Duration
	CPUTime                   time.Duration
	AverageUtilizationPercent float64
	CPUPerProcessedKpps       float64
	// CPUPerKpps is kept for compatibility and has the same value as
	// CPUPerProcessedKpps.
	CPUPerKpps float64
}

// ProcessCPUUsage calculates average CPU utilization and normalizes it by
// successfully processed server throughput.
func ProcessCPUUsage(start ProcessCPUSnapshot, end ProcessCPUSnapshot, processedPacketsPerSecond float64) ProcessCPUMetrics {
	wallDuration := end.wallTime.Sub(start.wallTime)
	cpuTime := end.cpuTime - start.cpuTime
	if wallDuration <= 0 || cpuTime < 0 {
		return ProcessCPUMetrics{}
	}

	avgCPU := cpuTime.Seconds() / wallDuration.Seconds() * 100
	cpuPerKpps := math.NaN()
	if processedPacketsPerSecond > 0 {
		cpuPerKpps = avgCPU / (processedPacketsPerSecond / 1000)
	}

	return ProcessCPUMetrics{
		Available:                 true,
		WallDuration:              wallDuration,
		CPUTime:                   cpuTime,
		AverageUtilizationPercent: avgCPU,
		CPUPerProcessedKpps:       cpuPerKpps,
		CPUPerKpps:                cpuPerKpps,
	}
}

// FormatCPUPercent formats average CPU utilization for tabular benchmark output.
func FormatCPUPercent(m ProcessCPUMetrics) string {
	if !m.Available {
		return "n/a"
	}

	return fmt.Sprintf("%.2f", m.AverageUtilizationPercent)
}

// FormatCPUPerProcessedKpps formats CPU percentage points spent per 1,000
// successfully processed packets/s.
func FormatCPUPerProcessedKpps(m ProcessCPUMetrics) string {
	if !m.Available || math.IsNaN(m.CPUPerProcessedKpps) {
		return "n/a"
	}

	return fmt.Sprintf("%.4f", m.CPUPerProcessedKpps)
}

// FormatCPUPerKpps is kept for compatibility. New benchmark reports should
// use FormatCPUPerProcessedKpps to make the denominator explicit.
func FormatCPUPerKpps(m ProcessCPUMetrics) string {
	return FormatCPUPerProcessedKpps(m)
}
