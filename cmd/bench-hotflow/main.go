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
		duration     = flag.Duration("duration", 10*time.Second, "Benchmark duration per scenario")
		totalPackets = flag.Uint64("total", 0, "Total packets per scenario; 0 means duration-based")

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

	metricsObserver := metrics.NewObserver()

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
		TargetAddr:   fmt.Sprintf("%s:%d", targetHost, port),
		Workers:      workers,
		Duration:     duration,
		TotalPackets: totalPackets,
		Mode:         benchmark.ModeFireAndForget,
		PayloadSize:  payloadSize,
		WriteTimeout: writeTimeout,
		SingleFlow:   true,
		BaseTEID:     1,
		BaseSequence: 1,
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

	serverSnapshot := metricsObserver.Snapshot()

	return scenarioResult{
		Name:     sc.Name,
		Mode:     sc.Mode,
		Client:   clientResult,
		Server:   serverSnapshot,
		CPU:      cpuMetrics,
		Duration: duration,
	}, nil
}

func printComparison(results []scenarioResult) {
	fmt.Println()
	fmt.Println("Single hot flow + heavy handler benchmark")
	fmt.Println("=========================================")
	fmt.Printf(
		"%-26s %-20s %14s %14s %14s %14s %14s %14s %14s\n",
		"scenario",
		"mode",
		"client_sent",
		"server_recv",
		"server_bytes",
		"client_pps",
		"avg_cpu_%",
		"cpu_per_kpps",
		"write_errors",
	)

	for _, item := range results {
		fmt.Printf(
			"%-26s %-20s %14d %14d %14d %14.2f %14s %14s %14d\n",
			item.Name,
			item.Mode,
			item.Client.SentPackets,
			item.Server.PacketsTotal,
			item.Server.BytesTotal,
			item.Client.PacketsPerSecond,
			benchmark.FormatCPUPercent(item.CPU),
			benchmark.FormatCPUPerKpps(item.CPU),
			item.Client.WriteErrors,
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
			packets := item.Server.PacketsBySocket[socketIndex]
			bytes := item.Server.BytesBySocket[socketIndex]

			fmt.Printf("socket[%d]: packets=%d bytes=%d\n", socketIndex, packets, bytes)
		}
	}

	fmt.Println()
	fmt.Println("Per-message-type distribution")
	fmt.Println("=============================")

	for _, item := range results {
		fmt.Printf("\n[%s]\n", item.Name)

		keys := metrics.SortedMessageTypeKeys(item.Server)
		if len(keys) == 0 {
			fmt.Println("no message type metrics")
			continue
		}

		for _, msgType := range keys {
			fmt.Printf("messageType[%d]: packets=%d\n", msgType, item.Server.PacketsByMessageType[msgType])
		}
	}
}
