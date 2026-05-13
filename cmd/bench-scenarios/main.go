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
	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	"github.com/quyenhl16/udp-gtp-go/server"
)

type scenario struct {
	Name        string
	Mode        server.Mode
	PortOffset  int
	ReusePort   bool
	EBPF        bool
	SocketCount int
}

type scenarioResult struct {
	Name   string
	Mode   server.Mode
	Result benchmark.Result
}

func main() {
	var (
		listenHost = flag.String("listen-host", "0.0.0.0", "Server listen host")
		targetHost = flag.String("target-host", "127.0.0.1", "Benchmark target host")
		basePort   = flag.Int("base-port", 21230, "Base UDP port for scenario servers")

		workers      = flag.Int("workers", 8, "Number of benchmark workers")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per scenario")
		totalPackets = flag.Uint64("total", 0, "Total packets per scenario; 0 means duration-based")

		benchMode    = flag.String("bench-mode", string(benchmark.ModeRequestResponse), "Benchmark mode: request_response or fire_and_forget")
		payloadSize  = flag.Int("payload-size", 0, "Payload size after the GTPv2-C header")
		readTimeout  = flag.Duration("read-timeout", 2*time.Second, "Read timeout")
		writeTimeout = flag.Duration("write-timeout", 2*time.Second, "Write timeout")

		s11MsgType = flag.Uint("s11-msg-type", 32, "GTPv2-C message type for S11 traffic")
		s10MsgType = flag.Uint("s10-msg-type", 128, "GTPv2-C message type for S10 traffic")
		s11Weight  = flag.Int("s11-weight", 4, "S11 traffic weight")
		s10Weight  = flag.Int("s10-weight", 1, "S10 traffic weight")

		warmup = flag.Duration("warmup", 500*time.Millisecond, "Warmup delay after starting each server")
	)

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	socketCount := *s11Weight + *s10Weight
	if socketCount <= 0 {
		log.Fatalf("invalid socket count derived from weights: %d", socketCount)
	}

	scenarios := []scenario{
		{
			Name:        "normal_1_socket",
			Mode:        server.ModeNormal,
			PortOffset:  0,
			ReusePort:   false,
			EBPF:        false,
			SocketCount: 1,
		},
		{
			Name:        "reuseport",
			Mode:        server.ModeReusePort,
			PortOffset:  1,
			ReusePort:   true,
			EBPF:        false,
			SocketCount: socketCount,
		},
		{
			Name:        "reuseport_ebpf",
			Mode:        server.ModeReusePortEBPF,
			PortOffset:  2,
			ReusePort:   true,
			EBPF:        true,
			SocketCount: socketCount,
		},
	}

	results := make([]scenarioResult, 0, len(scenarios))

	for _, sc := range scenarios {
		if ctx.Err() != nil {
			break
		}

		port := *basePort + sc.PortOffset

		log.Printf("starting scenario=%s mode=%s port=%d", sc.Name, sc.Mode, port)

		result, err := runScenario(
			ctx,
			sc,
			*listenHost,
			*targetHost,
			port,
			*workers,
			*duration,
			*totalPackets,
			benchmark.Mode(*benchMode),
			*payloadSize,
			*readTimeout,
			*writeTimeout,
			uint8(*s11MsgType),
			uint8(*s10MsgType),
			*s11Weight,
			*s10Weight,
			*warmup,
		)
		if err != nil {
			log.Fatalf("scenario %s failed: %v", sc.Name, err)
		}

		results = append(results, scenarioResult{
			Name:   sc.Name,
			Mode:   sc.Mode,
			Result: result,
		})
	}

	printComparison(results)
}

func runScenario(
	ctx context.Context,
	sc scenario,
	listenHost string,
	targetHost string,
	port int,
	workers int,
	duration time.Duration,
	totalPackets uint64,
	benchMode benchmark.Mode,
	payloadSize int,
	readTimeout time.Duration,
	writeTimeout time.Duration,
	s11MsgType uint8,
	s10MsgType uint8,
	s11Weight int,
	s10Weight int,
	warmup time.Duration,
) (benchmark.Result, error) {
	cfg := appconfig.Default()

	cfg.Listen.Network = "udp"
	cfg.Listen.Host = listenHost
	cfg.Listen.Port = port

	cfg.ReusePort.Enabled = sc.ReusePort
	cfg.ReusePort.SocketCount = sc.SocketCount
	cfg.ReusePort.S11Weight = s11Weight
	cfg.ReusePort.S10Weight = s10Weight

	cfg.EBPF.Enabled = sc.EBPF
	cfg.EBPF.S11MessageType = s11MsgType
	cfg.EBPF.S10MessageType = s10MsgType
	cfg.EBPF.AllowKernelFallback = true

	srv, err := server.NewWithMode(
		cfg,
		sc.Mode,
		server.OKHandler(),
		server.NopObserver{},
	)
	if err != nil {
		return benchmark.Result{}, fmt.Errorf("create server: %w", err)
	}

	if err := srv.Start(ctx); err != nil {
		return benchmark.Result{}, fmt.Errorf("start server: %w", err)
	}

	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("close scenario server %s: %v", sc.Name, err)
		}
	}()

	if warmup > 0 {
		select {
		case <-ctx.Done():
			return benchmark.Result{}, ctx.Err()
		case <-time.After(warmup):
		}
	}

	opts := benchmark.Options{
		TargetAddr:   fmt.Sprintf("%s:%d", targetHost, port),
		Workers:      workers,
		Duration:     duration,
		TotalPackets: totalPackets,
		Mode:         benchMode,
		PayloadSize:  payloadSize,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		Traffic: []benchmark.TrafficClass{
			{
				Name:        "S11",
				MessageType: s11MsgType,
				Weight:      s11Weight,
			},
			{
				Name:        "S10",
				MessageType: s10MsgType,
				Weight:      s10Weight,
			},
		},
		BaseTEID:     1,
		BaseSequence: 1,
	}

	result, err := benchmark.Run(ctx, opts)
	if err != nil {
		return benchmark.Result{}, fmt.Errorf("run benchmark: %w", err)
	}

	return result, nil
}

func printComparison(results []scenarioResult) {
	fmt.Println()
	fmt.Println("Benchmark comparison")
	fmt.Println("====================")
	fmt.Printf(
		"%-20s %-18s %12s %12s %12s %12s %12s %12s %12s\n",
		"scenario",
		"mode",
		"sent",
		"received",
		"pps",
		"avg",
		"p95",
		"p99",
		"timeouts",
	)

	for _, item := range results {
		r := item.Result

		fmt.Printf(
			"%-20s %-18s %12d %12d %12.2f %12s %12s %12s %12d\n",
			item.Name,
			item.Mode,
			r.SentPackets,
			r.ReceivedPackets,
			r.PacketsPerSecond,
			r.Latency.Avg,
			r.Latency.P95,
			r.Latency.P99,
			r.Timeouts,
		)
	}

	fmt.Println()
}