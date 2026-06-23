//go:build linux

package benchmark

import (
	"time"

	"golang.org/x/sys/unix"
)

// SampleProcessCPU captures cumulative user + system CPU time for this process.
func SampleProcessCPU() (ProcessCPUSnapshot, error) {
	var usage unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &usage); err != nil {
		return ProcessCPUSnapshot{}, err
	}

	return ProcessCPUSnapshot{
		wallTime: time.Now(),
		cpuTime:  timevalDuration(usage.Utime) + timevalDuration(usage.Stime),
	}, nil
}

func timevalDuration(tv unix.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second + time.Duration(tv.Usec)*time.Microsecond
}
