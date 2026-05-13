package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/quyenhl16/udp-gtp-go/benchmark"
)

func main() {
	var (
		targetAddr = flag.String("addr", "127.0.0.1:2123", "Target UDP address")
		mode       = flag.String("mode", string(benchmark.ModeRequestResponse), "Benchmark mode: request_response or fire_and_forget")

		workers      = flag.Int("workers", 1, "Number of concurrent UDP client workers")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration")
		totalPackets = flag.Uint64("total", 0, "Total packets to send across all workers; 0 means duration-based")

		payloadSize  = flag.Int("payload-size", 0, "Synthetic payload size after the fixed GTPv2-C header")
		readTimeout  = flag.Duration("read-timeout", 2*time.Second, "UDP read timeout for request-response mode")
		writeTimeout = flag.Duration("write-timeout", 2*time.Second, "UDP write timeout")

		s11MsgType = flag.Uint("s11-msg-type", 32, "GTPv2-C message type used for S11 traffic")
		s10MsgType = flag.Uint("s10-msg-type", 128, "GTPv2-C message type used for S10 traffic")

		s11Weight = flag.Int("s11-weight", 4, "Traffic weight for S11")
		s10Weight = flag.Int("s10-weight", 1, "Traffic weight for S10")

		baseTEID = flag.Uint("base-teid", 1, "Base TEID used for synthetic GTPv2-C packets")
		baseSeq  = flag.Uint("base-seq", 1, "Base sequence number used for synthetic GTPv2-C packets")
	)

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := benchmark.Options{
		TargetAddr:   *targetAddr,
		Workers:      *workers,
		Duration:     *duration,
		TotalPackets: *totalPackets,
		Mode:         benchmark.Mode(*mode),
		PayloadSize:  *payloadSize,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		BaseTEID:     uint32(*baseTEID),
		BaseSequence: uint32(*baseSeq),
		Traffic: []benchmark.TrafficClass{
			{
				Name:        "S11",
				MessageType: uint8(*s11MsgType),
				Weight:      *s11Weight,
			},
			{
				Name:        "S10",
				MessageType: uint8(*s10MsgType),
				Weight:      *s10Weight,
			},
		},
	}

	result, err := benchmark.Run(ctx, opts)
	if err != nil {
		log.Fatalf("benchmark failed: %v", err)
	}

	fmt.Print(benchmark.FormatResult(result))
}