//go:build linux

package reuseport

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenReusePortSocket(opts Options) (*net.UDPConn, int, error) {
	var socketFD int = -1

	lc := net.ListenConfig{
		Control: func(network, address string, rc syscall.RawConn) error {
			var controlErr error

			err := rc.Control(func(fd uintptr) {
				socketFD = int(fd)

				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					controlErr = fmt.Errorf("set SO_REUSEADDR: %w", err)
					return
				}

				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					controlErr = fmt.Errorf("set SO_REUSEPORT: %w", err)
					return
				}

				if opts.ReadBufferBytes > 0 {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, opts.ReadBufferBytes); err != nil {
						controlErr = fmt.Errorf("set SO_RCVBUF: %w", err)
						return
					}
				}

				if opts.WriteBufferBytes > 0 {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, opts.WriteBufferBytes); err != nil {
						controlErr = fmt.Errorf("set SO_SNDBUF: %w", err)
						return
					}
				}
			})
			if err != nil {
				return fmt.Errorf("socket control: %w", err)
			}
			return controlErr
		},
	}

	pc, err := lc.ListenPacket(
		context.Background(),
		opts.Network,
		net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port)),
	)
	if err != nil {
		return nil, 0, fmt.Errorf("listen packet: %w", err)
	}

	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, 0, fmt.Errorf("listen packet returned non-UDP connection: %T", pc)
	}

	if opts.ReadBufferBytes > 0 {
		if err := conn.SetReadBuffer(opts.ReadBufferBytes); err != nil {
			_ = conn.Close()
			return nil, 0, fmt.Errorf("set read buffer: %w", err)
		}
	}

	if opts.WriteBufferBytes > 0 {
		if err := conn.SetWriteBuffer(opts.WriteBufferBytes); err != nil {
			_ = conn.Close()
			return nil, 0, fmt.Errorf("set write buffer: %w", err)
		}
	}

	if socketFD < 0 {
		_ = conn.Close()
		return nil, 0, fmt.Errorf("socket fd was not captured")
	}

	return conn, socketFD, nil
}