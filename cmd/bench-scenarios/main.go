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

type scenarioResults struct {
	Name string
	Mode server.Mode
	Runs []scenarioResult
}

func main() {
	var (
		listenHost = flag.String("listen-host", "0.0.0.0", "Server listen host")
		targetHost = flag.String("target-host", "127.0.0.1", "Benchmark target host")
		basePort   = flag.Int("base-port", 21230, "Base UDP port for scenario servers")

		workers      = flag.Int("workers", 8, "Number of benchmark workers")
		runs         = flag.Int("runs", 5, "Number of runs per server mode")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per run")
		totalPackets = flag.Uint64("total", 0, "Total packets per run; 0 means duration-based")

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
	if *runs <= 0 {
		log.Fatalf("runs must be > 0: got %d", *runs)
	}

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

	results := make([]scenarioResults, 0, len(scenarios))

	for _, sc := range scenarios {
		if ctx.Err() != nil {
			break
		}

		port := *basePort + sc.PortOffset

		group := scenarioResults{Name: sc.Name, Mode: sc.Mode, Runs: make([]scenarioResult, 0, *runs)}
		for run := 1; run <= *runs; run++ {
			log.Printf("starting scenario=%s mode=%s run=%d/%d port=%d", sc.Name, sc.Mode, run, *runs, port)

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
				log.Fatalf("scenario %s run %d/%d failed: %v", sc.Name, run, *runs, err)
			}
			group.Runs = append(group.Runs, result)
		}

		results = append(results, group)
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

func printComparison(results []scenarioResults) {
	fmt.Println()
	fmt.Println("Benchmark comparison")
	fmt.Println("====================")
	fmt.Println("Each value is: mean [95% confidence interval]")

	for _, group := range results {
		fmt.Printf("\n[%s] mode=%s runs=%d\n", group.Name, group.Mode, len(group.Runs))
		printEstimate("client_sent", collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Client.SentPackets) }), 2)
		printEstimate("server_recv", collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.PacketsTotal) }), 2)
		printEstimate("processed", collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.ProcessedPacketsTotal) }), 2)
		printEstimate("processed_kpps", collect(group.Runs, processedKpps), 2)
		printEstimate("delivery_%", collect(group.Runs, func(item scenarioResult) float64 {
			return benchmark.DeliveryRatio(item.Client.SentPackets, item.Server.PacketsTotal)
		}), 2)
		printDurationEstimate("p50", collectLatency(group.Runs, 50))
		printDurationEstimate("p95", collectLatency(group.Runs, 95))
		printDurationEstimate("p99", collectLatency(group.Runs, 99))
		printEstimate("inferred_drops", collect(group.Runs, func(item scenarioResult) float64 {
			return float64(benchmark.InferredDrops(item.Client.SentPackets, item.Server.PacketsTotal))
		}), 2)
		printEstimate("rx_overflow", collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.ReceiveOverflowTotal) }), 2)
		printEstimate("write_errors", collect(group.Runs, func(item scenarioResult) float64 {
			return float64(item.Client.WriteErrors + item.Server.WriteErrorsTotal)
		}), 2)
		fmt.Printf("%-24s %s\n", "affinity_violations", "n/a")
		printEstimate("avg_cpu_%", collectAvailableCPU(group.Runs, func(cpu benchmark.ProcessCPUMetrics) float64 {
			return cpu.AverageUtilizationPercent
		}), 2)
		printEstimate("cpu/processed_kpps", collectAvailableCPU(group.Runs, func(cpu benchmark.ProcessCPUMetrics) float64 {
			return cpu.CPUPerProcessedKpps
		}), 4)
	}

	fmt.Println()
}

func processedKpps(item scenarioResult) float64 {
	duration := item.CPU.WallDuration
	if duration <= 0 {
		duration = item.Client.Duration
	}
	return benchmark.PacketsPerSecond(item.Server.ProcessedPacketsTotal, duration) / 1000
}

func collect(items []scenarioResult, value func(scenarioResult) float64) []float64 {
	values := make([]float64, 0, len(items))
	for _, item := range items {
		values = append(values, value(item))
	}
	return values
}

func collectAvailableCPU(items []scenarioResult, value func(benchmark.ProcessCPUMetrics) float64) []float64 {
	values := make([]float64, 0, len(items))
	for _, item := range items {
		if item.CPU.Available {
			values = append(values, value(item.CPU))
		}
	}
	return values
}

func collectLatency(items []scenarioResult, percentile int) []time.Duration {
	values := make([]time.Duration, 0, len(items))
	for _, item := range items {
		latencyCount := uint64(item.Client.Latency.Count)
		p50, p95, p99 := item.Client.Latency.P50, item.Client.Latency.P95, item.Client.Latency.P99
		if latencyCount == 0 {
			latencyCount = item.Server.ProcessingLatency.Count
			p50, p95, p99 = item.Server.ProcessingLatency.P50, item.Server.ProcessingLatency.P95, item.Server.ProcessingLatency.P99
		}
		if latencyCount == 0 {
			continue
		}
		switch percentile {
		case 50:
			values = append(values, p50)
		case 95:
			values = append(values, p95)
		case 99:
			values = append(values, p99)
		}
	}
	return values
}

func printEstimate(name string, values []float64, precision int) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatMeanCI95(values, precision))
}

func printDurationEstimate(name string, values []time.Duration) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatDurationMeanCI95(values))
}
