package udp

import (
	"fmt"
	"net"
)

// UDPConn is the concrete implementation of Conn.
type UDPConn struct {
	conn *net.UDPConn
	opts Options
}

// Listen creates and binds a UDP socket using the provided options.
func Listen(opts Options) (*UDPConn, error) {
	opts.Normalize()

	lc := net.ListenConfig{
		Control: controlFunc(opts),
	}

	pc, err := lc.ListenPacket(
		contextBackground(),
		opts.Network,
		joinHostPort(opts.Host, opts.Port),
	)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s/%s:%d: %w", opts.Network, opts.Host, opts.Port, err)
	}

	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, fmt.Errorf("listen packet returned non-UDP connection: %T", pc)
	}

	if err := applyConnOptions(udpConn, opts); err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("apply udp options: %w", err)
	}

	return &UDPConn{
		conn: udpConn,
		opts: opts,
	}, nil
}

// Close closes the UDP connection.
func (c *UDPConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// LocalAddr returns the local bound address.
func (c *UDPConn) LocalAddr() net.Addr {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

// RawConn returns the underlying net.UDPConn.
func (c *UDPConn) RawConn() *net.UDPConn {
	if c == nil {
		return nil
	}
	return c.conn
}