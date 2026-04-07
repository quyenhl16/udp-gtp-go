package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	rphook "github.com/quyenhl16/udp-gtp-go/ebpf/hooks/reuseport"
	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
)

func main() {
	configPath := flag.String("config", "", "Path to JSON config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		log.Fatalf("demo failed: %v", err)
	}
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	group, err := rpsock.Open(buildReuseportOptions(cfg))
	if err != nil {
		return err
	}
	defer func() {
		if err := group.Close(); err != nil {
			log.Printf("close reuseport group: %v", err)
		}
	}()

	module := rphook.New()
	if err := module.Load(); err != nil {
		return err
	}
	defer func() {
		if err := module.Close(); err != nil {
			log.Printf("close reuseport module: %v", err)
		}
	}()

	if err := module.UpdateConfig(buildReuseportModuleConfig(cfg)); err != nil {
		return err
	}

	if err := module.SyncSockArray(group); err != nil {
		return err
	}

	if err := module.Attach(group); err != nil {
		return err
	}

	log.Printf("demo started on %s with %d sockets", addrString(group), group.Len())
	log.Printf(
		"classifier config: s11_msg=%d s10_msg=%d s11_pool=%d:%d s10_pool=%d:%d fallback=%d:%d",
		cfg.EBPF.S11MessageType,
		cfg.EBPF.S10MessageType,
		0,
		cfg.ReusePort.S11Weight,
		cfg.ReusePort.S11Weight,
		cfg.ReusePort.S10Weight,
		0,
		cfg.ReusePort.SocketCount,
	)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	startReaders(ctx, group, &wg)

	<-ctx.Done()
	log.Printf("shutdown signal received")

	cancel()

	if err := group.Close(); err != nil {
		log.Printf("close reuseport group during shutdown: %v", err)
	}

	wg.Wait()
	log.Printf("demo stopped")

	return nil
}

func loadConfig(configPath string) (appconfig.AppConfig, error) {
	if configPath == "" {
		return appconfig.Load()
	}
	return appconfig.LoadWithFile(configPath)
}

func buildReuseportOptions(cfg appconfig.AppConfig) rpsock.Options {
	return rpsock.Options{
		Network:          cfg.Listen.Network,
		Host:             cfg.Listen.Host,
		Port:             cfg.Listen.Port,
		SocketCount:      cfg.ReusePort.SocketCount,
		ReadBufferBytes:  cfg.ReusePort.RecvBufferBytes,
		WriteBufferBytes: cfg.ReusePort.SendBufferBytes,
	}
}

func buildReuseportModuleConfig(cfg appconfig.AppConfig) rphook.Config {
	return rphook.Config{
		S11MessageType:      cfg.EBPF.S11MessageType,
		S10MessageType:      cfg.EBPF.S10MessageType,
		S11PoolBase:         0,
		S11PoolSize:         uint32(cfg.ReusePort.S11Weight),
		S10PoolBase:         uint32(cfg.ReusePort.S11Weight),
		S10PoolSize:         uint32(cfg.ReusePort.S10Weight),
		FallbackPoolBase:    0,
		FallbackPoolSize:    uint32(cfg.ReusePort.SocketCount),
		AllowKernelFallback: cfg.EBPF.AllowKernelFallback,
	}
}

func startReaders(ctx context.Context, group *rpsock.Group, wg *sync.WaitGroup) {
	conns := group.Conns()

	for i, conn := range conns {
		if conn == nil {
			continue
		}

		wg.Add(1)
		go func(index int, c *net.UDPConn) {
			defer wg.Done()
			readLoop(ctx, index, c)
		}(i, conn)
	}
}

func readLoop(ctx context.Context, index int, conn *net.UDPConn) {
	buf := make([]byte, 4096)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("socket[%d] set read deadline: %v", index, err)
			return
		}

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}

			log.Printf("socket[%d] read error: %v", index, err)
			continue
		}

		payload := append([]byte(nil), buf[:n]...)
		msgType, ok := extractMessageType(payload)

		if ok {
			log.Printf("socket[%d] recv %d bytes from %s msgType=%d", index, n, addr.String(), msgType)
		} else {
			log.Printf("socket[%d] recv %d bytes from %s msgType=unknown", index, n, addr.String())
		}

		if _, err := conn.WriteToUDP([]byte("ok"), addr); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("socket[%d] write error: %v", index, err)
		}
	}
}

func extractMessageType(payload []byte) (uint8, bool) {
	if len(payload) < 2 {
		return 0, false
	}
	return payload[1], true
}

func addrString(group *rpsock.Group) string {
	if group == nil || group.LocalAddr() == nil {
		return ""
	}
	return group.LocalAddr().String()
}