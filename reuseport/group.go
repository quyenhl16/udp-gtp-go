package reuseport

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

// Group represents a UDP reuseport socket group.
type Group struct {
	mu      sync.RWMutex
	opts    Options
	conns   []*net.UDPConn
	fds     []int
	closed  bool
}

// Open creates a UDP reuseport socket group with the provided options.
func Open(opts Options) (*Group, error) {
	opts.Normalize()

	if err := validateOptions(opts); err != nil {
		return nil, err
	}

	conns := make([]*net.UDPConn, 0, opts.SocketCount)
	fds := make([]int, 0, opts.SocketCount)

	for i := 0; i < opts.SocketCount; i++ {
		conn, fd, err := listenReusePortSocket(opts)
		if err != nil {
			closeAll(conns)
			return nil, fmt.Errorf("open reuseport socket %d/%d: %w", i, opts.SocketCount, err)
		}

		conns = append(conns, conn)
		fds = append(fds, fd)
	}

	return &Group{
		opts:  opts,
		conns: conns,
		fds:   fds,
	}, nil
}

// Close closes all sockets in the group.
func (g *Group) Close() error {
	if g == nil {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return nil
	}

	var firstErr error
	for _, conn := range g.conns {
		if conn == nil {
			continue
		}
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	g.closed = true
	g.conns = nil
	g.fds = nil

	return firstErr
}

// Options returns a copy of the group options.
func (g *Group) Options() Options {
	if g == nil {
		return Options{}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.opts
}

// Len returns the number of sockets in the group.
func (g *Group) Len() int {
	if g == nil {
		return 0
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	return len(g.conns)
}

// Conn returns the socket at the given index.
func (g *Group) Conn(index int) (*net.UDPConn, error) {
	if g == nil {
		return nil, ErrEmptyGroup
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.conns) == 0 {
		return nil, ErrEmptyGroup
	}
	if index < 0 || index >= len(g.conns) {
		return nil, ErrIndexOutOfRange
	}

	return g.conns[index], nil
}

// Conns returns a shallow copy of the socket slice.
func (g *Group) Conns() []*net.UDPConn {
	if g == nil {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]*net.UDPConn, len(g.conns))
	copy(out, g.conns)
	return out
}

// FD returns the raw file descriptor for the socket at the given index.
func (g *Group) FD(index int) (int, error) {
	if g == nil {
		return 0, ErrEmptyGroup
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.fds) == 0 {
		return 0, ErrEmptyGroup
	}
	if index < 0 || index >= len(g.fds) {
		return 0, ErrIndexOutOfRange
	}

	return g.fds[index], nil
}

// FDs returns a copy of all raw file descriptors.
func (g *Group) FDs() []int {
	if g == nil {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]int, len(g.fds))
	copy(out, g.fds)
	return out
}

// LocalAddr returns the local address of the first socket in the group.
func (g *Group) LocalAddr() net.Addr {
	if g == nil {
		return nil
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.conns) == 0 || g.conns[0] == nil {
		return nil
	}
	return g.conns[0].LocalAddr()
}

// AddrString returns the normalized host:port string of the group.
func (g *Group) AddrString() string {
	if g == nil {
		return ""
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	return net.JoinHostPort(g.opts.Host, strconv.Itoa(g.opts.Port))
}

func validateOptions(opts Options) error {
	if opts.SocketCount <= 0 {
		return fmt.Errorf("%w: %d", ErrInvalidSocketCount, opts.SocketCount)
	}
	if opts.Port < 0 || opts.Port > 65535 {
		return fmt.Errorf("invalid port: %d", opts.Port)
	}
	switch opts.Network {
	case "udp", "udp4", "udp6":
		return nil
	default:
		return fmt.Errorf("invalid network %q", opts.Network)
	}
}

func closeAll(conns []*net.UDPConn) {
	for _, conn := range conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
}