package benchmark

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type workerResult struct {
	sentPackets     uint64
	receivedPackets uint64
	sentBytes       uint64
	receivedBytes   uint64
	writeErrors     uint64
	readErrors      uint64
	timeouts        uint64
	latencies       []time.Duration
}

// Run executes a UDP benchmark against the configured target.
func Run(ctx context.Context, opts Options) (Result, error) {
	opts.Normalize()

	if err := opts.Validate(); err != nil {
		return Result{}, err
	}

	target, err := net.ResolveUDPAddr("udp", opts.TargetAddr)
	if err != nil {
		return Result{}, fmt.Errorf("resolve target address %q: %w", opts.TargetAddr, err)
	}

	runCtx := ctx
	if runCtx == nil {
		runCtx = context.Background()
	}

	if opts.Duration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(runCtx, opts.Duration)
		defer cancel()
	}

	startedAt := time.Now()

	results := make(chan workerResult, opts.Workers)
	var wg sync.WaitGroup
	var sentCounter atomic.Uint64

	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func(workerIndex int) {
			defer wg.Done()
			results <- runWorker(runCtx, workerIndex, target, opts, &sentCounter)
		}(i)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	final := Result{
		Target:    opts.TargetAddr,
		Mode:      opts.Mode,
		Workers:   opts.Workers,
		StartedAt: startedAt,
	}

	var latencies []time.Duration

	for wr := range results {
		final.SentPackets += wr.sentPackets
		final.ReceivedPackets += wr.receivedPackets
		final.SentBytes += wr.sentBytes
		final.ReceivedBytes += wr.receivedBytes
		final.WriteErrors += wr.writeErrors
		final.ReadErrors += wr.readErrors
		final.Timeouts += wr.timeouts
		latencies = append(latencies, wr.latencies...)
	}

	final.EndedAt = time.Now()
	final.Duration = final.EndedAt.Sub(final.StartedAt)

	if final.Duration > 0 {
		final.PacketsPerSecond = float64(final.SentPackets) / final.Duration.Seconds()
		final.BytesPerSecond = float64(final.SentBytes) / final.Duration.Seconds()
	}

	final.Latency = summarizeLatencies(latencies)

	return final, nil
}

func runWorker(
	ctx context.Context,
	workerIndex int,
	target *net.UDPAddr,
	opts Options,
	sentCounter *atomic.Uint64,
) workerResult {
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return workerResult{
			writeErrors: 1,
		}
	}
	defer conn.Close()

	picker, err := newTrafficPicker(opts.Traffic, defaultSeed(workerIndex))
	if err != nil {
		return workerResult{
			writeErrors: 1,
		}
	}

	var out workerResult
	readBuf := make([]byte, 4096)

	for {
		if ctx.Err() != nil {
			return out
		}

		if opts.TotalPackets > 0 {
			n := sentCounter.Add(1)
			if n > opts.TotalPackets {
				return out
			}
		}

		tc := picker.Next()
		packet := BuildGTPv2Message(
			tc.MessageType,
			opts.BaseTEID+uint32(workerIndex),
			opts.BaseSequence+uint32(out.sentPackets),
			opts.PayloadSize,
		)

		if opts.WriteTimeout > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(opts.WriteTimeout))
		} else {
			_ = conn.SetWriteDeadline(time.Time{})
		}

		start := time.Now()
		n, err := conn.Write(packet)
		if err != nil {
			out.writeErrors++
			continue
		}

		out.sentPackets++
		out.sentBytes += uint64(n)

		if opts.Mode == ModeFireAndForget {
			continue
		}

		if opts.ReadTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(opts.ReadTimeout))
		} else {
			_ = conn.SetReadDeadline(time.Time{})
		}

		n, err = conn.Read(readBuf)
		if err != nil {
			if ctx.Err() != nil {
				return out
			}

			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				out.timeouts++
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				return out
			}

			out.readErrors++
			continue
		}

		out.receivedPackets++
		out.receivedBytes += uint64(n)
		out.latencies = append(out.latencies, time.Since(start))
	}
}
