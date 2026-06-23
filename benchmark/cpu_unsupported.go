//go:build !linux

package benchmark

// SampleProcessCPU reports that process CPU usage is unavailable on this OS.
func SampleProcessCPU() (ProcessCPUSnapshot, error) {
	return ProcessCPUSnapshot{}, ErrCPUUsageUnavailable
}
