package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"
	"time"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	"github.com/quyenhl16/udp-gtp-go/server"
)

func main() {
	var (
		configPath           string
		toggleReuseport      bool
		toggleDelay          time.Duration
	)

	flag.StringVar(&configPath, "config", "", "Path to JSON config file")
	flag.BoolVar(&toggleReuseport, "toggle-reuseport-module", false, "Toggle the reuseport eBPF module at runtime")
	flag.DurationVar(&toggleDelay, "toggle-delay", 10*time.Second, "Delay before disable and before re-enable when toggle mode is enabled")
	flag.Parse()

	if err := run(configPath, toggleReuseport, toggleDelay); err != nil {
		log.Fatalf("demo failed: %v", err)
	}
}

func run(configPath string, toggleReuseport bool, toggleDelay time.Duration) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	srv, err := server.New(
		cfg,
		server.OKHandler(),
		server.PacketLogger(log.Printf),
	)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if err := srv.Close(); err != nil {
			log.Printf("close server: %v", err)
		}
	}()

	log.Printf("server mode: %s", srv.Mode())

	if addr := srv.Addr(); addr != nil {
		log.Printf("server listen address: %s", addr.String())
	}

	logStartupState(srv)

	if toggleReuseport {
		go runReuseportToggleDemo(ctx, srv, toggleDelay)
	}

	<-ctx.Done()
	log.Printf("shutdown signal received")

	return nil
}

func loadConfig(configPath string) (appconfig.AppConfig, error) {
	if configPath == "" {
		return appconfig.Load()
	}

	return appconfig.LoadWithFile(configPath)
}

func logStartupState(srv *server.Server) {
	state, err := srv.ModuleState("reuseport")
	if err != nil {
		log.Printf("reuseport module state: unavailable (%v)", err)
		return
	}

	log.Printf("reuseport module state: %s", state)
}

func runReuseportToggleDemo(ctx context.Context, srv *server.Server, delay time.Duration) {
	if delay <= 0 {
		delay = 10 * time.Second
	}

	state, err := srv.ModuleState("reuseport")
	if err != nil {
		log.Printf("toggle demo skipped: reuseport module not available (%v)", err)
		return
	}

	log.Printf("toggle demo started: current reuseport module state=%s", state)

	if !sleepWithContext(ctx, delay) {
		return
	}

	log.Printf("toggle demo: disabling module reuseport")
	if err := srv.DisableModule(ctx, "reuseport"); err != nil {
		log.Printf("disable module reuseport failed: %v", err)
	} else {
		logModuleState(srv, "reuseport")
	}

	if !sleepWithContext(ctx, delay) {
		return
	}

	log.Printf("toggle demo: enabling module reuseport")
	if err := srv.EnableModule(ctx, "reuseport"); err != nil {
		log.Printf("enable module reuseport failed: %v", err)
	} else {
		logModuleState(srv, "reuseport")
	}
}

func logModuleState(srv *server.Server, name string) {
	state, err := srv.ModuleState(name)
	if err != nil {
		log.Printf("module %s state unavailable: %v", name, err)
		return
	}

	log.Printf("module %s state: %s", name, state)
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}