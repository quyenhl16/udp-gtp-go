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
	"github.com/quyenhl16/udp-gtp-go/metrics"
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
	Client benchmark.Result
	Server metrics.Snapshot
	CPU    benchmark.ProcessCPUMetrics
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

		results = append(results, result)
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
) (scenarioResult, error) {
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

	metricsObserver := metrics.NewEndToEndObserver()
	srv, err := server.NewWithMode(
		cfg,
		sc.Mode,
		server.OKHandler(),
		metricsObserver,
	)
	if err != nil {
		return scenarioResult{}, fmt.Errorf("create server: %w", err)
	}

	if err := srv.Start(ctx); err != nil {
		return scenarioResult{}, fmt.Errorf("start server: %w", err)
	}

	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("close scenario server %s: %v", sc.Name, err)
		}
	}()

	if warmup > 0 {
		select {
		case <-ctx.Done():
			return scenarioResult{}, ctx.Err()
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
		BaseTEID:           1,
		BaseSequence:       1,
		TrackServerLatency: true,
	}

	cpuStart, cpuStartErr := benchmark.SampleProcessCPU()
	clientResult, err := benchmark.Run(ctx, opts)
	if err != nil {
		return scenarioResult{}, fmt.Errorf("run benchmark: %w", err)
	}
	cpuEnd, cpuEndErr := benchmark.SampleProcessCPU()
	serverSnapshot := metricsObserver.Snapshot()
	cpuMetrics := benchmark.ProcessCPUMetrics{}
	if cpuStartErr == nil && cpuEndErr == nil {
		cpuMetrics = benchmark.ProcessCPUUsage(cpuStart, cpuEnd, 0)
		processedPPS := benchmark.PacketsPerSecond(serverSnapshot.ProcessedPacketsTotal, cpuMetrics.WallDuration)
		cpuMetrics = benchmark.ProcessCPUUsage(cpuStart, cpuEnd, processedPPS)
	}

	return scenarioResult{
		Name:   sc.Name,
		Mode:   sc.Mode,
		Client: clientResult,
		Server: serverSnapshot,
		CPU:    cpuMetrics,
	}, nil
}

func printComparison(results []scenarioResult) {
	fmt.Println()
	fmt.Println("Benchmark comparison")
	fmt.Println("====================")
	fmt.Printf(
		"%-20s %12s %12s %12s %15s %11s %12s %12s %12s %16s %12s %14s %14s %20s\n",
		"mode",
		"client_sent",
		"server_recv",
		"processed",
		"processed_kpps",
		"delivery_%",
		"p50",
		"p95",
		"p99",
		"drop/overflow",
		"write_errs",
		"affinity_viol",
		"avg_cpu_%",
		"cpu/processed_kpps",
	)

	for _, item := range results {
		duration := item.CPU.WallDuration
		if duration <= 0 {
			duration = item.Client.Duration
		}
		processedKpps := benchmark.PacketsPerSecond(item.Server.ProcessedPacketsTotal, duration) / 1000
		latencyCount := uint64(item.Client.Latency.Count)
		p50, p95, p99 := item.Client.Latency.P50, item.Client.Latency.P95, item.Client.Latency.P99
		if latencyCount == 0 {
			latencyCount = item.Server.ProcessingLatency.Count
			p50, p95, p99 = item.Server.ProcessingLatency.P50, item.Server.ProcessingLatency.P95, item.Server.ProcessingLatency.P99
		}

		fmt.Printf(
			"%-20s %12d %12d %12d %15.2f %11.2f %12s %12s %12s %16s %12d %14s %14s %20s\n",
			item.Name,
			item.Client.SentPackets,
			item.Server.PacketsTotal,
			item.Server.ProcessedPacketsTotal,
			processedKpps,
			benchmark.DeliveryRatio(item.Client.SentPackets, item.Server.PacketsTotal),
			benchmark.FormatLatency(latencyCount, p50),
			benchmark.FormatLatency(latencyCount, p95),
			benchmark.FormatLatency(latencyCount, p99),
			fmt.Sprintf("%d/%d", benchmark.InferredDrops(item.Client.SentPackets, item.Server.PacketsTotal), item.Server.ReceiveOverflowTotal),
			item.Client.WriteErrors+item.Server.WriteErrorsTotal,
			"n/a",
			benchmark.FormatCPUPercent(item.CPU),
			benchmark.FormatCPUPerProcessedKpps(item.CPU),
		)
	}

	fmt.Println()
}
