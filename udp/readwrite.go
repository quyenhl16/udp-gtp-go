package udp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// ReadPacket reads a single UDP packet into the provided buffer.
func (c *UDPConn) ReadPacket(ctx context.Context, buf []byte) (Packet, error) {
	if c == nil || c.conn == nil {
		return Packet{}, ErrNilUDPConn
	}

	if deadline, ok := contextDeadline(ctx, c.opts.ReadTimeout); ok {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return Packet{}, fmt.Errorf("set read deadline: %w", err)
		}
	} else {
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			return Packet{}, fmt.Errorf("clear read deadline: %w", err)
		}
	}

	n, addr, err := c.conn.ReadFrom(buf)
	if err != nil {
		return Packet{}, err
	}

	data := make([]byte, n)
	copy(data, buf[:n])

	return Packet{
		Data:       data,
		RemoteAddr: addr,
		LocalAddr:  c.conn.LocalAddr(),
		ReceivedAt: time.Now(),
	}, nil
}

// WritePacket writes a UDP packet to the specified remote address.
func (c *UDPConn) WritePacket(ctx context.Context, payload []byte, addr net.Addr) (int, error) {
	if c == nil || c.conn == nil {
		return 0, ErrNilUDPConn
	}
	if addr == nil {
		return 0, ErrNilRemoteAddr
	}

	if deadline, ok := contextDeadline(ctx, c.opts.WriteTimeout); ok {
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return 0, fmt.Errorf("set write deadline: %w", err)
		}
	} else {
		if err := c.conn.SetWriteDeadline(time.Time{}); err != nil {
			return 0, fmt.Errorf("clear write deadline: %w", err)
		}
	}

	n, err := c.conn.WriteTo(payload, addr)
	if err != nil {
		return n, err
	}
	return n, nil
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func contextDeadline(ctx context.Context, fallback time.Duration) (time.Time, bool) {
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			return deadline, true
		}
	}

	if fallback > 0 {
		return time.Now().Add(fallback), true
	}

	return time.Time{}, false
}