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
	CPUPerKpps                float64
}

// ProcessCPUUsage calculates average CPU utilization between two snapshots.
func ProcessCPUUsage(start ProcessCPUSnapshot, end ProcessCPUSnapshot, packetsPerSecond float64) ProcessCPUMetrics {
	wallDuration := end.wallTime.Sub(start.wallTime)
	cpuTime := end.cpuTime - start.cpuTime
	if wallDuration <= 0 || cpuTime < 0 {
		return ProcessCPUMetrics{}
	}

	avgCPU := cpuTime.Seconds() / wallDuration.Seconds() * 100
	cpuPerKpps := math.NaN()
	if packetsPerSecond > 0 {
		cpuPerKpps = avgCPU / (packetsPerSecond / 1000)
	}

	return ProcessCPUMetrics{
		Available:                 true,
		WallDuration:              wallDuration,
		CPUTime:                   cpuTime,
		AverageUtilizationPercent: avgCPU,
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

// FormatCPUPerKpps formats CPU percentage points spent per 1,000 packets/s.
func FormatCPUPerKpps(m ProcessCPUMetrics) string {
	if !m.Available || math.IsNaN(m.CPUPerKpps) {
		return "n/a"
	}

	return fmt.Sprintf("%.4f", m.CPUPerKpps)
}
