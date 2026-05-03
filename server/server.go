package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	rphook "github.com/quyenhl16/udp-gtp-go/ebpf/hooks/reuseport"
	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
)

// Server owns the transport sockets, the optional reuseport eBPF module,
// and the packet read loops.
type Server struct {
	mu       sync.Mutex
	cfg      appconfig.AppConfig
	mode     Mode
	handler  Handler
	observer Observer

	socketSet socketSet
	group     *rpsock.Group
	module    *rphook.Module

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	started bool
	closed  bool
}

// New creates a new Server.
func New(cfg appconfig.AppConfig, handler Handler, observer Observer) (*Server, error) {
	cfg.Normalize()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if handler == nil {
		return nil, ErrNilHandler
	}
	if observer == nil {
		observer = NopObserver{}
	}

	return &Server{
		cfg:      cfg,
		mode:     EffectiveMode(cfg),
		handler:  handler,
		observer: observer,
	}, nil
}

// Start initializes runtime resources and starts packet readers.
func (s *Server) Start(parent context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return ErrServerStarted
	}

	ctx := parent
	if ctx == nil {
		ctx = context.Background()
	}

	s.ctx, s.cancel = context.WithCancel(ctx)

	set, group, err := openSocketSet(buildConfig{
		udp:       BuildUDPOptions(s.cfg),
		reuseport: BuildReuseportOptions(s.cfg),
	}, s.mode)
	if err != nil {
		s.cancel()
		return fmt.Errorf("open socket set: %w", err)
	}

	module, err := s.initEBPF(group)
	if err != nil {
		_ = set.Close()
		s.cancel()
		return err
	}

	s.socketSet = set
	s.group = group
	s.module = module
	s.started = true

	s.startReadersLocked()

	s.observer.OnStart(s.socketSet.LocalAddr(), s.socketSet.Len())

	go s.watchContext()

	return nil
}

// Close stops packet readers and releases runtime resources.
func (s *Server) Close() error {
	s.mu.Lock()

	if !s.started {
		s.mu.Unlock()
		return ErrServerNotStarted
	}
	if s.closed {
		s.mu.Unlock()
		return nil
	}

	s.closed = true

	cancel := s.cancel
	socketSet := s.socketSet
	module := s.module

	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var firstErr error

	if socketSet != nil {
		if err := socketSet.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.wg.Wait()

	if module != nil {
		if err := module.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	s.observer.OnStop()

	return firstErr
}

// Mode returns the effective runtime mode.
func (s *Server) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mode
}

// Addr returns the local address if the server has started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.socketSet == nil {
		return nil
	}

	return s.socketSet.LocalAddr()
}

// ReuseportGroup returns the reuseport group when reuseport mode is active.
func (s *Server) ReuseportGroup() *rpsock.Group {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.group
}

// ReuseportModule returns the reuseport eBPF module when enabled.
func (s *Server) ReuseportModule() *rphook.Module {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.module
}

func (s *Server) initEBPF(group *rpsock.Group) (*rphook.Module, error) {
	if !s.cfg.EBPF.Enabled {
		return nil, nil
	}
	if s.mode != ModeReusePort || group == nil {
		return nil, ErrReuseportEBPFRequiresReusePort
	}

	module := rphook.New()

	if err := module.Load(); err != nil {
		return nil, fmt.Errorf("load reuseport module: %w", err)
	}

	if err := module.UpdateConfig(BuildReuseportModuleConfig(s.cfg)); err != nil {
		_ = module.Close()
		return nil, fmt.Errorf("update reuseport module config: %w", err)
	}

	if err := module.SyncSockArray(group); err != nil {
		_ = module.Close()
		return nil, fmt.Errorf("sync reuseport sockarray: %w", err)
	}

	if err := module.Attach(group); err != nil {
		_ = module.Close()
		return nil, fmt.Errorf("attach reuseport module: %w", err)
	}

	return module, nil
}

func (s *Server) watchContext() {
	<-s.ctx.Done()
	_ = s.Close()
}

func (s *Server) startReadersLocked() {
	conns := s.socketSet.Conns()

	for i, conn := range conns {
		if conn == nil {
			continue
		}

		s.wg.Add(1)

		go func(index int, c *net.UDPConn) {
			defer s.wg.Done()
			s.readLoop(index, c)
		}(i, conn)
	}
}

func (s *Server) readLoop(index int, conn *net.UDPConn) {
	buf := make([]byte, 4096)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			if s.ctx.Err() != nil {
				return
			}

			s.observer.OnReadError(index, err)
			return
		}

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}

			s.observer.OnReadError(index, err)
			continue
		}

		pkt := Packet{
			SocketIndex: index,
			Data:        append([]byte(nil), buf[:n]...),
			RemoteAddr:  addr,
			LocalAddr:   conn.LocalAddr(),
			ReceivedAt:  time.Now(),
		}

		s.observer.OnPacketReceived(pkt)

		writer := &udpResponseWriter{
			conn: conn,
			pkt:  pkt,
			obs:  s.observer,
		}

		if err := s.handler.HandlePacket(s.ctx, pkt, writer); err != nil {
			s.observer.OnHandleError(pkt, err)
		}
	}
}

type udpResponseWriter struct {
	conn *net.UDPConn
	pkt  Packet
	obs  Observer
}

// Write sends a packet to the provided address through the same UDP socket.
func (w *udpResponseWriter) Write(payload []byte, addr *net.UDPAddr) (int, error) {
	if w == nil || w.conn == nil {
		return 0, fmt.Errorf("response writer is nil")
	}
	if addr == nil {
		return 0, fmt.Errorf("remote address is nil")
	}

	n, err := w.conn.WriteToUDP(payload, addr)
	if err != nil && w.obs != nil {
		w.obs.OnWriteError(w.pkt, err)
	}

	return n, err
}