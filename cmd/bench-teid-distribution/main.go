package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os/signal"
	"sort"
	"sync"
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
	Affinity affinitySnapshot
}

type scenarioResults struct {
	Name string
	Mode server.Mode
	Runs []scenarioResult
}

type affinityObserver struct {
	mu            sync.Mutex
	socketByTEID  map[uint32]int
	packetsByTEID map[uint32]uint64
	violations    uint64
}

type affinitySnapshot struct {
	TEIDCount  int
	Violations uint64
	Samples    []teidSample
}

type teidSample struct {
	TEID        uint32
	SocketIndex int
	Packets     uint64
}

func newAffinityObserver() *affinityObserver {
	return &affinityObserver{
		socketByTEID:  map[uint32]int{},
		packetsByTEID: map[uint32]uint64{},
	}
}

func (o *affinityObserver) OnStart(addr net.Addr, socketCount int) {}
func (o *affinityObserver) OnStop()                                {}
func (o *affinityObserver) OnReadError(socketIndex int, err error) {}
func (o *affinityObserver) OnHandleError(pkt server.Packet, err error) {
}
func (o *affinityObserver) OnWriteError(pkt server.Packet, err error) {
}

func (o *affinityObserver) OnPacketReceived(pkt server.Packet) {
	header, err := gtpv2.DecodeHeader(pkt.Data)
	if err != nil || !header.HasTEID() {
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	if socketIndex, ok := o.socketByTEID[header.TEID]; ok && socketIndex != pkt.SocketIndex {
		o.violations++
	} else {
		o.socketByTEID[header.TEID] = pkt.SocketIndex
	}

	o.packetsByTEID[header.TEID]++
}

func (o *affinityObserver) Snapshot(limit int) affinitySnapshot {
	o.mu.Lock()
	defer o.mu.Unlock()

	samples := make([]teidSample, 0, len(o.socketByTEID))
	for teid, socketIndex := range o.socketByTEID {
		samples = append(samples, teidSample{
			TEID:        teid,
			SocketIndex: socketIndex,
			Packets:     o.packetsByTEID[teid],
		})
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i].TEID < samples[j].TEID })
	if limit > 0 && len(samples) > limit {
		samples = samples[:limit]
	}

	return affinitySnapshot{
		TEIDCount:  len(o.socketByTEID),
		Violations: o.violations,
		Samples:    samples,
	}
}

func main() {
	var (
		listenHost = flag.String("listen-host", "0.0.0.0", "Server listen host")
		targetHost = flag.String("target-host", "127.0.0.1", "Benchmark target host")
		basePort   = flag.Int("base-port", 21400, "Base UDP port for scenario servers")

		workers      = flag.Int("workers", 8, "Number of client workers sharing one UDP socket")
		runs         = flag.Int("runs", 5, "Number of runs per server mode")
		socketCount  = flag.Int("sockets", 8, "Number of reuseport sockets")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per run")
		totalPackets = flag.Uint64("total", 0, "Total packets per run; 0 means duration-based")

		msgType      = flag.Uint("msg-type", 32, "GTPv2-C message type for all generated packets")
		baseTEID     = flag.Uint("base-teid", 1, "First TEID in the generated TEID range")
		teidCount    = flag.Uint("teid-count", 1024, "Number of sequential TEIDs to cycle through")
		payloadSize  = flag.Int("payload-size", 0, "Payload size after the GTPv2-C header")
		writeTimeout = flag.Duration("write-timeout", 2*time.Second, "UDP write timeout")

		warmup      = flag.Duration("warmup", 500*time.Millisecond, "Warmup delay after server start")
		drain       = flag.Duration("drain", 2*time.Second, "Drain delay after client benchmark before reading server metrics")
		sampleLimit = flag.Int("sample-teids", 16, "Number of TEID affinity samples to print per scenario")
	)

	flag.Parse()

	if *runs <= 0 {
		log.Fatalf("runs must be > 0: got %d", *runs)
	}
	if *socketCount <= 0 {
		log.Fatalf("sockets must be > 0: got %d", *socketCount)
	}
	if *teidCount == 0 {
		log.Fatalf("teid-count must be > 0")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	scenarios := []scenario{
		{
			Name:        "udp_1_socket",
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
			SocketCount: *socketCount,
		},
		{
			Name:        "reuseport_ebpf_teid",
			Mode:        server.ModeReusePortEBPF,
			PortOffset:  2,
			ReusePort:   true,
			EBPF:        true,
			SocketCount: *socketCount,
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
				uint8(*msgType),
				uint32(*baseTEID),
				uint32(*teidCount),
				*payloadSize,
				*writeTimeout,
				*warmup,
				*drain,
				*sampleLimit,
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
	msgType uint8,
	baseTEID uint32,
	teidCount uint32,
	payloadSize int,
	writeTimeout time.Duration,
	warmup time.Duration,
	drain time.Duration,
	sampleLimit int,
) (scenarioResult, error) {
	cfg := appconfig.Default()

	cfg.Listen.Network = "udp"
	cfg.Listen.Host = listenHost
	cfg.Listen.Port = port

	cfg.ReusePort.Enabled = sc.ReusePort
	cfg.ReusePort.SocketCount = sc.SocketCount
	cfg.ReusePort.S11Weight = sc.SocketCount
	cfg.ReusePort.S10Weight = 0

	cfg.EBPF.Enabled = sc.EBPF
	cfg.EBPF.S11MessageType = msgType
	cfg.EBPF.S10MessageType = alternateMessageType(msgType)
	cfg.EBPF.SelectionMode = rphook.SelectionModeGTPTEID
	cfg.EBPF.AllowKernelFallback = true

	metricsObserver := metrics.NewEndToEndObserver()
	affinityObserver := newAffinityObserver()

	srv, err := server.NewWithMode(
		cfg,
		sc.Mode,
		server.HandlerFunc(func(ctx context.Context, pkt server.Packet, w server.ResponseWriter) error {
			return nil
		}),
		server.NewMultiObserver(metricsObserver, affinityObserver),
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

	cpuStart, cpuStartErr := benchmark.SampleProcessCPU()

	clientResult, err := benchmark.Run(ctx, benchmark.Options{
		TargetAddr:         fmt.Sprintf("%s:%d", targetHost, port),
		Workers:            workers,
		Duration:           duration,
		TotalPackets:       totalPackets,
		Mode:               benchmark.ModeFireAndForget,
		PayloadSize:        payloadSize,
		WriteTimeout:       writeTimeout,
		SingleFlow:         false,
		BaseTEID:           baseTEID,
		TEIDCount:          teidCount,
		BaseSequence:       1,
		TrackServerLatency: true,
		Traffic: []benchmark.TrafficClass{
			{
				Name:        "GTP",
				MessageType: msgType,
				Weight:      1,
			},
		},
	})
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
		Affinity: affinityObserver.Snapshot(sampleLimit),
	}, nil
}

func printComparison(results []scenarioResults) {
	fmt.Println()
	fmt.Println("TEID-aware worker distribution benchmark")
	fmt.Println("========================================")
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
		printEstimate("affinity_violations", collect(group.Runs, func(item scenarioResult) float64 {
			return float64(item.Affinity.Violations)
		}), 2)
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
			fmt.Printf(
				"socket[%d]: packets=%s bytes=%s\n",
				socketIndex,
				benchmark.FormatMeanCI95(packets, 2),
				benchmark.FormatMeanCI95(bytes, 2),
			)
		}
	}

	fmt.Println()
	fmt.Println("TEID affinity samples")
	fmt.Println("=====================")
	for _, group := range results {
		fmt.Printf("\n[%s]\n", group.Name)
		teids := sampleTEIDs(group.Runs)
		if len(teids) == 0 {
			fmt.Println("no TEID samples")
			continue
		}

		for _, teid := range teids {
			fmt.Printf(
				"teid[%d]: sockets_by_run=%v packets=%s\n",
				teid,
				sampleSockets(group.Runs, teid),
				benchmark.FormatMeanCI95(samplePackets(group.Runs, teid), 2),
			)
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

func sampleTEIDs(items []scenarioResult) []uint32 {
	seen := map[uint32]struct{}{}
	for _, item := range items {
		for _, sample := range item.Affinity.Samples {
			seen[sample.TEID] = struct{}{}
		}
	}
	teids := make([]uint32, 0, len(seen))
	for teid := range seen {
		teids = append(teids, teid)
	}
	sort.Slice(teids, func(i, j int) bool { return teids[i] < teids[j] })
	return teids
}

func sampleSockets(items []scenarioResult, teid uint32) []int {
	sockets := make([]int, 0, len(items))
	for _, item := range items {
		socket := -1
		for _, sample := range item.Affinity.Samples {
			if sample.TEID == teid {
				socket = sample.SocketIndex
				break
			}
		}
		sockets = append(sockets, socket)
	}
	return sockets
}

func samplePackets(items []scenarioResult, teid uint32) []float64 {
	packets := make([]float64, 0, len(items))
	for _, item := range items {
		var count uint64
		for _, sample := range item.Affinity.Samples {
			if sample.TEID == teid {
				count = sample.Packets
				break
			}
		}
		packets = append(packets, float64(count))
	}
	return packets
}

func printEstimate(name string, values []float64, precision int) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatMeanCI95(values, precision))
}

func printDurationEstimate(name string, values []time.Duration) {
	fmt.Printf("%-24s %s\n", name, benchmark.FormatDurationMeanCI95(values))
}

func alternateMessageType(messageType uint8) uint8 {
	if messageType == 255 {
		return 254
	}

	return messageType + 1
}
