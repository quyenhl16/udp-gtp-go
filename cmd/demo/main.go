package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	"github.com/quyenhl16/udp-gtp-go/server"
)

func main() {
	configPath := flag.String("config", "", "Path to JSON config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	srv, err := server.New(
		cfg,
		server.OKHandler(),
		server.PacketLogger(log.Printf),
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

	log.Printf("demo exited")
}

func loadConfig(configPath string) (appconfig.AppConfig, error) {
	if configPath == "" {
		return appconfig.Load()
	}
	return appconfig.LoadWithFile(configPath)
}