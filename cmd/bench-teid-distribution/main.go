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
		socketCount  = flag.Int("sockets", 8, "Number of reuseport sockets")
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per scenario")
		totalPackets = flag.Uint64("total", 0, "Total packets per scenario; 0 means duration-based")

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

	results := make([]scenarioResult, 0, len(scenarios))
	for _, sc := range scenarios {
		if ctx.Err() != nil {
			break
		}

		port := *basePort + sc.PortOffset
		log.Printf("scenario=%s mode=%s port=%d", sc.Name, sc.Mode, port)

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

	metricsObserver := metrics.NewObserver()
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
		TargetAddr:   fmt.Sprintf("%s:%d", targetHost, port),
		Workers:      workers,
		Duration:     duration,
		TotalPackets: totalPackets,
		Mode:         benchmark.ModeFireAndForget,
		PayloadSize:  payloadSize,
		WriteTimeout: writeTimeout,
		SingleFlow:   true,
		BaseTEID:     baseTEID,
		TEIDCount:    teidCount,
		BaseSequence: 1,
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

	cpuEnd, cpuEndErr := benchmark.SampleProcessCPU()
	cpuMetrics := benchmark.ProcessCPUMetrics{}
	if cpuStartErr == nil && cpuEndErr == nil {
		cpuMetrics = benchmark.ProcessCPUUsage(cpuStart, cpuEnd, clientResult.PacketsPerSecond)
	}

	if drain > 0 {
		select {
		case <-ctx.Done():
			return scenarioResult{}, ctx.Err()
		case <-time.After(drain):
		}
	}

	return scenarioResult{
		Name:     sc.Name,
		Mode:     sc.Mode,
		Client:   clientResult,
		Server:   metricsObserver.Snapshot(),
		CPU:      cpuMetrics,
		Affinity: affinityObserver.Snapshot(sampleLimit),
	}, nil
}

func printComparison(results []scenarioResult) {
	fmt.Println()
	fmt.Println("TEID-aware worker distribution benchmark")
	fmt.Println("========================================")
	fmt.Printf(
		"%-24s %-20s %14s %14s %14s %14s %14s %14s %14s\n",
		"scenario",
		"mode",
		"client_sent",
		"server_recv",
		"client_pps",
		"avg_cpu_%",
		"cpu_per_kpps",
		"teids_seen",
		"affinity_viol",
	)

	for _, item := range results {
		fmt.Printf(
			"%-24s %-20s %14d %14d %14.2f %14s %14s %14d %14d\n",
			item.Name,
			item.Mode,
			item.Client.SentPackets,
			item.Server.PacketsTotal,
			item.Client.PacketsPerSecond,
			benchmark.FormatCPUPercent(item.CPU),
			benchmark.FormatCPUPerKpps(item.CPU),
			item.Affinity.TEIDCount,
			item.Affinity.Violations,
		)
	}

	fmt.Println()
	fmt.Println("Per-socket distribution")
	fmt.Println("=======================")
	for _, item := range results {
		fmt.Printf("\n[%s]\n", item.Name)
		keys := metrics.SortedSocketKeys(item.Server)
		if len(keys) == 0 {
			fmt.Println("no socket metrics")
			continue
		}

		for _, socketIndex := range keys {
			fmt.Printf(
				"socket[%d]: packets=%d bytes=%d\n",
				socketIndex,
				item.Server.PacketsBySocket[socketIndex],
				item.Server.BytesBySocket[socketIndex],
			)
		}
	}

	fmt.Println()
	fmt.Println("TEID affinity samples")
	fmt.Println("=====================")
	for _, item := range results {
		fmt.Printf("\n[%s]\n", item.Name)
		if len(item.Affinity.Samples) == 0 {
			fmt.Println("no TEID samples")
			continue
		}

		for _, sample := range item.Affinity.Samples {
			fmt.Printf(
				"teid[%d]: socket=%d packets=%d\n",
				sample.TEID,
				sample.SocketIndex,
				sample.Packets,
			)
		}
	}
}

func alternateMessageType(messageType uint8) uint8 {
	if messageType == 255 {
		return 254
	}

	return messageType + 1
}
