//go:build linux

package udp

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// controlFunc returns the socket control callback for ListenConfig.
//
// This package intentionally does not enable SO_REUSEPORT here.
// Reuseport-specific behavior belongs to the reuseport package.
func controlFunc(opts Options) func(string, string, syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		var controlErr error

		err := rc.Control(func(fd uintptr) {
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
	}
}

// applyConnOptions applies post-bind connection options.
func applyConnOptions(conn *net.UDPConn, opts Options) error {
	if conn == nil {
		return ErrNilUDPConn
	}

	if opts.ReadBufferBytes > 0 {
		if err := conn.SetReadBuffer(opts.ReadBufferBytes); err != nil {
			return fmt.Errorf("set read buffer: %w", err)
		}
	}

	if opts.WriteBufferBytes > 0 {
		if err := conn.SetWriteBuffer(opts.WriteBufferBytes); err != nil {
			return fmt.Errorf("set write buffer: %w", err)
		}
	}

	return nil
}