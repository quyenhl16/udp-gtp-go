package server

import (
	"context"
	"net"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	rphook "github.com/quyenhl16/udp-gtp-go/ebpf/hooks/reuseport"
	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
)

// BuildReuseportOptions converts application config into reuseport socket options.
func BuildReuseportOptions(cfg appconfig.AppConfig) rpsock.Options {
	return rpsock.Options{
		Network:          cfg.Listen.Network,
		Host:             cfg.Listen.Host,
		Port:             cfg.Listen.Port,
		SocketCount:      cfg.ReusePort.SocketCount,
		ReadBufferBytes:  cfg.ReusePort.RecvBufferBytes,
		WriteBufferBytes: cfg.ReusePort.SendBufferBytes,
	}
}

// BuildReuseportModuleConfig converts application config into eBPF runtime config.
func BuildReuseportModuleConfig(cfg appconfig.AppConfig) rphook.Config {
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

// EchoHandler returns a simple default handler for smoke tests.
func EchoHandler(payload []byte) Handler {
	reply := append([]byte(nil), payload...)

	return HandlerFunc(func(ctx context.Context, pkt Packet, w ResponseWriter) error {
		_, err := w.Write(reply, pkt.RemoteAddr)
		return err
	})
}

// OKHandler returns a simple "ok" response handler for smoke tests.
func OKHandler() Handler {
	return HandlerFunc(func(ctx context.Context, pkt Packet, w ResponseWriter) error {
		_, err := w.Write([]byte("ok"), pkt.RemoteAddr)
		return err
	})
}

// PacketLogger returns an Observer that logs to the provided function.
func PacketLogger(logf func(format string, args ...any)) Observer {
	if logf == nil {
		return NopObserver{}
	}

	return packetLogger{logf: logf}
}

type packetLogger struct {
	logf func(format string, args ...any)
}

func (l packetLogger) OnStart(addr net.Addr, socketCount int) {
	l.logf("server started on %s with %d sockets", addr, socketCount)
}

func (l packetLogger) OnStop() {
	l.logf("server stopped")
}

func (l packetLogger) OnPacketReceived(pkt Packet) {
	if pkt.RemoteAddr != nil {
		l.logf(
			"socket[%d] recv %d bytes from %s",
			pkt.SocketIndex,
			len(pkt.Data),
			pkt.RemoteAddr.String(),
		)
	}
}

func (l packetLogger) OnReadError(socketIndex int, err error) {
	l.logf("socket[%d] read error: %v", socketIndex, err)
}

func (l packetLogger) OnHandleError(pkt Packet, err error) {
	l.logf("socket[%d] handle error: %v", pkt.SocketIndex, err)
}

func (l packetLogger) OnWriteError(pkt Packet, err error) {
	l.logf("socket[%d] write error: %v", pkt.SocketIndex, err)
}