package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	"github.com/quyenhl16/udp-gtp-go/metrics"
	"github.com/quyenhl16/udp-gtp-go/server"
)

func main() {
	configPath := flag.String("config", "", "Path to JSON config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	metricsObserver := metrics.NewObserver()
	observer := server.NewMultiObserver(
		server.PacketLogger(log.Printf),
		metricsObserver,
	)

	srv, err := server.New(
		cfg,
		server.OKHandler(),
		observer,
	)
	if err != nil {
		log.Fatalf("create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("start server: %v", err)
	}

	<-ctx.Done()

	if err := srv.Close(); err != nil {
		log.Printf("close server: %v", err)
	}

	snap := metricsObserver.Snapshot()

	log.Printf("packets_total=%d bytes_total=%d", snap.PacketsTotal, snap.BytesTotal)
	log.Printf(
		"read_errors=%d handle_errors=%d write_errors=%d",
		snap.ReadErrorsTotal,
		snap.HandleErrorsTotal,
		snap.WriteErrorsTotal,
	)

	for _, socketIndex := range metrics.SortedSocketKeys(snap) {
		log.Printf(
			"socket[%d]: packets=%d bytes=%d",
			socketIndex,
			snap.PacketsBySocket[socketIndex],
			snap.BytesBySocket[socketIndex],
		)
	}

	for _, msgType := range metrics.SortedMessageTypeKeys(snap) {
		log.Printf(
			"messageType[%d]: packets=%d",
			msgType,
			snap.PacketsByMessageType[msgType],
		)
	}

	log.Printf("demo exited")
}

func loadConfig(configPath string) (appconfig.AppConfig, error) {
	if configPath == "" {
		return appconfig.Load()
	}
	return appconfig.LoadWithFile(configPath)
}