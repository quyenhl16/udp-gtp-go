package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	appconfig "github.com/quyenhl16/udp-gtp-go/config"
	rphook "github.com/quyenhl16/udp-gtp-go/ebpf/hooks/reuseport"
	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
)

// Server owns UDP sockets, optional reuseport group, optional eBPF module,
// and packet read loops.
type Server struct {
	mu       sync.Mutex
	cfg      appconfig.AppConfig
	mode     Mode
	handler  Handler
	observer Observer

	normalConn *net.UDPConn

	group  *rpsock.Group
	module *rphook.Module

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	started bool
	closed  bool
}

// New creates a new Server and derives the mode from config.
func New(cfg appconfig.AppConfig, handler Handler, observer Observer) (*Server, error) {
	return NewWithMode(cfg, ModeFromConfig(cfg), handler, observer)
}

// NewWithMode creates a new Server with an explicit mode.
func NewWithMode(cfg appconfig.AppConfig, mode Mode, handler Handler, observer Observer) (*Server, error) {
	cfg.Normalize()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if handler == nil {
		return nil, ErrNilHandler
	}
	if observer == nil {
		observer = NopObserver{}
	}

	switch mode {
	case ModeNormal, ModeReusePort, ModeReusePortEBPF:
	default:
		return nil, fmt.Errorf("invalid server mode: %q", mode)
	}

	return &Server{
		cfg:      cfg,
		mode:     mode,
		handler:  handler,
		observer: observer,
	}, nil
}

// Mode returns the server startup mode.
func (s *Server) Mode() Mode {
	if s == nil {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	return s.mode
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

	var err error

	switch s.mode {
	case ModeNormal:
		err = s.startNormalLocked()

	case ModeReusePort:
		err = s.startReusePortLocked(false)

	case ModeReusePortEBPF:
		err = s.startReusePortLocked(true)

	default:
		err = fmt.Errorf("invalid server mode: %q", s.mode)
	}

	if err != nil {
		s.cancel()
		return err
	}

	s.started = true

	go s.watchContext()

	return nil
}

func (s *Server) startNormalLocked() error {
	conn, err := listenNormalUDP(s.cfg)
	if err != nil {
		return fmt.Errorf("listen normal udp: %w", err)
	}

	s.normalConn = conn
	s.startReaderLocked(0, conn)

	s.observer.OnStart(conn.LocalAddr(), 1)

	return nil
}

func (s *Server) startReusePortLocked(enableEBPF bool) error {
	group, err := rpsock.Open(BuildReuseportOptions(s.cfg))
	if err != nil {
		return fmt.Errorf("open reuseport group: %w", err)
	}

	var module *rphook.Module

	if enableEBPF {
		module = rphook.New()
		if err := module.Load(); err != nil {
			_ = group.Close()
			return fmt.Errorf("load reuseport module: %w", err)
		}

		if err := module.UpdateConfig(BuildReuseportModuleConfig(s.cfg)); err != nil {
			_ = module.Close()
			_ = group.Close()
			return fmt.Errorf("update reuseport module config: %w", err)
		}

		if err := module.SyncSockArray(group); err != nil {
			_ = module.Close()
			_ = group.Close()
			return fmt.Errorf("sync reuseport sockarray: %w", err)
		}

		if err := module.Attach(group); err != nil {
			_ = module.Close()
			_ = group.Close()
			return fmt.Errorf("attach reuseport module: %w", err)
		}
	}

	s.group = group
	s.module = module

	for i, conn := range group.Conns() {
		if conn == nil {
			continue
		}
		s.startReaderLocked(i, conn)
	}

	s.observer.OnStart(group.LocalAddr(), group.Len())

	return nil
}

// Close stops packet readers and releases all runtime resources.
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
	normalConn := s.normalConn
	group := s.group
	module := s.module

	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	var firstErr error

	if normalConn != nil {
		if err := normalConn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if group != nil {
		if err := group.Close(); err != nil && firstErr == nil {
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

// Addr returns the local address if the server has started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.normalConn != nil {
		return s.normalConn.LocalAddr()
	}

	if s.group != nil {
		return s.group.LocalAddr()
	}

	return nil
}

// ReuseportGroup returns the runtime socket group.
func (s *Server) ReuseportGroup() *rpsock.Group {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.group
}

// ReuseportModule returns the runtime reuseport module.
func (s *Server) ReuseportModule() *rphook.Module {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.module
}

func (s *Server) watchContext() {
	<-s.ctx.Done()
	_ = s.Close()
}

func (s *Server) startReaderLocked(index int, conn *net.UDPConn) {
	s.wg.Add(1)

	go func() {
		defer s.wg.Done()
		s.readLoop(index, conn)
	}()
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

func listenNormalUDP(cfg appconfig.AppConfig) (*net.UDPConn, error) {
	addr := net.JoinHostPort(cfg.Listen.Host, strconv.Itoa(cfg.Listen.Port))

	udpAddr, err := net.ResolveUDPAddr(cfg.Listen.Network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %s: %w", addr, err)
	}

	conn, err := net.ListenUDP(cfg.Listen.Network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}

	if cfg.ReusePort.RecvBufferBytes > 0 {
		if err := conn.SetReadBuffer(cfg.ReusePort.RecvBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("set read buffer: %w", err)
		}
	}

	if cfg.ReusePort.SendBufferBytes > 0 {
		if err := conn.SetWriteBuffer(cfg.ReusePort.SendBufferBytes); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("set write buffer: %w", err)
		}
	}

	return conn, nil
}