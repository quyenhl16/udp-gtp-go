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
	rphook "github.com/quyenhl16/udp-gtp-go/ebpf/hooks/reuseport"
	"github.com/quyenhl16/udp-gtp-go/gtpv2"
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
	Name     string
	Mode     server.Mode
	Client   benchmark.Result
	Server   metrics.Snapshot
	CPU      benchmark.ProcessCPUMetrics
	Duration time.Duration
}

type scenarioResults struct {
	Name string
	Mode server.Mode
	Runs []scenarioResult
}

type heavyHandler struct {
	heavyMessageType uint8
	heavyDelay       time.Duration
	reply            bool
}

func (h heavyHandler) HandlePacket(ctx context.Context, pkt server.Packet, w server.ResponseWriter) error {
	msgType, err := gtpv2.MessageType(pkt.Data)
	if err == nil && msgType == h.heavyMessageType && h.heavyDelay > 0 {
		timer := time.NewTimer(h.heavyDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	if h.reply {
		_, err := w.Write([]byte("ok"), pkt.RemoteAddr)
		return err
	}

	return nil
}

func main() {
	var (
		listenHost = flag.String("listen-host", "0.0.0.0", "Server listen host")
		targetHost = flag.String("target-host", "127.0.0.1", "Benchmark target host")
		basePort   = flag.Int("base-port", 21300, "Base UDP port for scenario servers")

		workers      = flag.Int("workers", 8, "Number of client workers sharing one UDP socket")
		runs         = flag.Int("runs", 5, "Number of runs per server mode")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per run")
		totalPackets = flag.Uint64("total", 0, "Total packets per run; 0 means duration-based")

		payloadSize  = flag.Int("payload-size", 0, "Payload size after the GTPv2-C header")
		writeTimeout = flag.Duration("write-timeout", 2*time.Second, "UDP write timeout")

		s11MsgType = flag.Uint("s11-msg-type", 32, "GTPv2-C message type for hot S11 traffic")
		s10MsgType = flag.Uint("s10-msg-type", 128, "GTPv2-C message type for S10 traffic")

		s11Weight = flag.Int("s11-weight", 100, "S11 traffic weight")
		s10Weight = flag.Int("s10-weight", 0, "S10 traffic weight")

		s11PoolWeight = flag.Int("s11-pool-weight", 4, "S11 socket pool size")
		s10PoolWeight = flag.Int("s10-pool-weight", 1, "S10 socket pool size")

		heavyDelay = flag.Duration("heavy-delay", 200*time.Microsecond, "Simulated handler cost for S11 packets")
		warmup     = flag.Duration("warmup", 500*time.Millisecond, "Warmup delay after server start")
		drain      = flag.Duration("drain", 2*time.Second, "Drain delay after client benchmark before reading server metrics")
	)

	flag.Parse()
	if *runs <= 0 {
		log.Fatalf("runs must be > 0: got %d", *runs)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	socketCount := *s11PoolWeight + *s10PoolWeight
	if socketCount <= 0 {
		log.Fatalf("invalid socket count: %d", socketCount)
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
			Name:        "reuseport_kernel_hash",
			Mode:        server.ModeReusePort,
			PortOffset:  1,
			ReusePort:   true,
			EBPF:        false,
			SocketCount: socketCount,
		},
		{
			Name:        "reuseport_ebpf_seq_shard",
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
			log.Printf("scenario=%s mode=%s run=%d/%d port=%d", sc.Name, sc.Mode, run, *runs, port)

			result, err := runScenario(
				ctx,
				sc,
				*listenHost,
				*targetHost,
				port,
				*workers,
				*duration,
				*totalPackets,
				*payloadSize,
				*writeTimeout,
				uint8(*s11MsgType),
				uint8(*s10MsgType),
				*s11Weight,
				*s10Weight,
				*s11PoolWeight,
				*s10PoolWeight,
				*heavyDelay,
				*warmup,
				*drain,
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
	payloadSize int,
	writeTimeout time.Duration,
	s11MsgType uint8,
	s10MsgType uint8,
	s11Weight int,
	s10Weight int,
	s11PoolWeight int,
	s10PoolWeight int,
	heavyDelay time.Duration,
	warmup time.Duration,
	drain time.Duration,
) (scenarioResult, error) {
	cfg := appconfig.Default()

	cfg.Listen.Network = "udp"
	cfg.Listen.Host = listenHost
	cfg.Listen.Port = port

	cfg.ReusePort.Enabled = sc.ReusePort
	cfg.ReusePort.SocketCount = sc.SocketCount
	cfg.ReusePort.S11Weight = s11PoolWeight
	cfg.ReusePort.S10Weight = s10PoolWeight

	cfg.EBPF.Enabled = sc.EBPF
	cfg.EBPF.S11MessageType = s11MsgType
	cfg.EBPF.S10MessageType = s10MsgType
	cfg.EBPF.SelectionMode = rphook.SelectionModeGTPSequence
	cfg.EBPF.AllowKernelFallback = true

	metricsObserver := metrics.NewEndToEndObserver()

	srv, err := server.NewWithMode(
		cfg,
		sc.Mode,
		heavyHandler{
			heavyMessageType: s11MsgType,
			heavyDelay:       heavyDelay,
			reply:            false,
		},
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
			log.Printf("close server scenario=%s: %v", sc.Name, err)
		}
	}()

	if warmup > 0 {
		select {
		case <-ctx.Done():
			return scenarioResult{}, ctx.Err()
		case <-time.After(warmup):
		}
	}

	clientOpts := benchmark.Options{
		TargetAddr:         fmt.Sprintf("%s:%d", targetHost, port),
		Workers:            workers,
		Duration:           duration,
		TotalPackets:       totalPackets,
		Mode:               benchmark.ModeFireAndForget,
		PayloadSize:        payloadSize,
		WriteTimeout:       writeTimeout,
		SingleFlow:         true,
		BaseTEID:           1,
		BaseSequence:       1,
		TrackServerLatency: true,
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
	}

	cpuStart, cpuStartErr := benchmark.SampleProcessCPU()

	clientResult, err := benchmark.Run(ctx, clientOpts)
	if err != nil {
		return scenarioResult{}, fmt.Errorf("run client benchmark: %w", err)
	}

	if drain > 0 {
		select {
		case <-ctx.Done():
			return scenarioResult{}, ctx.Err()
		case <-time.After(drain):
		}
	}

	serverSnapshot := metricsObserver.Snapshot()
	cpuEnd, cpuEndErr := benchmark.SampleProcessCPU()
	cpuMetrics := benchmark.ProcessCPUMetrics{}
	if cpuStartErr == nil && cpuEndErr == nil {
		cpuMetrics = benchmark.ProcessCPUUsage(cpuStart, cpuEnd, 0)
		processedPPS := benchmark.PacketsPerSecond(serverSnapshot.ProcessedPacketsTotal, cpuMetrics.WallDuration)
		cpuMetrics = benchmark.ProcessCPUUsage(cpuStart, cpuEnd, processedPPS)
	}

	return scenarioResult{
		Name:     sc.Name,
		Mode:     sc.Mode,
		Client:   clientResult,
		Server:   serverSnapshot,
		CPU:      cpuMetrics,
		Duration: duration,
	}, nil
}

func printComparison(results []scenarioResults) {
	fmt.Println()
	fmt.Println("Single hot flow + heavy handler benchmark")
	fmt.Println("=========================================")
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
		printDurationEstimate("p50", collectServerLatency(group.Runs, 50))
		printDurationEstimate("p95", collectServerLatency(group.Runs, 95))
		printDurationEstimate("p99", collectServerLatency(group.Runs, 99))
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
	fmt.Println("Per-socket distribution")
	fmt.Println("=======================")

	for _, group := range results {
		fmt.Printf("\n[%s]\n", group.Name)

		keys := socketKeys(group.Runs)
		if len(keys) == 0 {
			fmt.Println("no socket metrics")
			continue
		}

		for _, socketIndex := range keys {
			packets := collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.PacketsBySocket[socketIndex]) })
			bytes := collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.BytesBySocket[socketIndex]) })

			fmt.Printf("socket[%d]: packets=%s bytes=%s\n", socketIndex, benchmark.FormatMeanCI95(packets, 2), benchmark.FormatMeanCI95(bytes, 2))
		}
	}

	fmt.Println()
	fmt.Println("Per-message-type distribution")
	fmt.Println("=============================")

	for _, group := range results {
		fmt.Printf("\n[%s]\n", group.Name)

		keys := messageTypeKeys(group.Runs)
		if len(keys) == 0 {
			fmt.Println("no message type metrics")
			continue
		}

		for _, msgType := range keys {
			packets := collect(group.Runs, func(item scenarioResult) float64 { return float64(item.Server.PacketsByMessageType[msgType]) })
			fmt.Printf("messageType[%d]: packets=%s\n", msgType, benchmark.FormatMeanCI95(packets, 2))
		}
	}
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

func collectServerLatency(items []scenarioResult, percentile int) []time.Duration {
	values := make([]time.Duration, 0, len(items))
	for _, item := range items {
		latency := item.Server.ProcessingLatency
		if latency.Count == 0 {
			continue
		}
		switch percentile {
		case 50:
			values = append(values, latency.P50)
		case 95:
			values = append(values, latency.P95)
		case 99:
			values = append(values, latency.P99)
		}
	}
	return values
}

func socketKeys(items []scenarioResult) []int {
	merged := metrics.Snapshot{PacketsBySocket: map[int]uint64{}}
	for _, item := range items {
		for key := range item.Server.PacketsBySocket {
			merged.PacketsBySocket[key] = 1
		}
	}
	return metrics.SortedSocketKeys(merged)
}

func messageTypeKeys(items []scenarioResult) []uint8 {
	merged := metrics.Snapshot{PacketsByMessageType: map[uint8]uint64{}}
	for _, item := range items {
		for key := range item.Server.PacketsByMessageType {
			merged.PacketsByMessageType[key] = 1
		}
	}
	return metrics.SortedMessageTypeKeys(merged)
}

func printEstimate(name string, values []float64, precision int) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatMeanCI95(values, precision))
}

func printDurationEstimate(name string, values []time.Duration) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatDurationMeanCI95(values))
}
