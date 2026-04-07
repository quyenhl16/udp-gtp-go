//go:build linux

package reuseport

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// attachProgram attaches the reuseport selector to a socket in the reuseport group.
func attachProgram(socketFD int, prog *ciliumebpf.Program) error {
	if prog == nil {
		return fmt.Errorf("ebpf program is nil")
	}

	progFD := prog.FD()
	if progFD < 0 {
		return fmt.Errorf("invalid ebpf program fd: %d", progFD)
	}

	if err := unix.SetsockoptInt(socketFD, unix.SOL_SOCKET, unix.SO_ATTACH_REUSEPORT_EBPF, progFD); err != nil {
		return fmt.Errorf("setsockopt SO_ATTACH_REUSEPORT_EBPF: %w", err)
	}

	return nil
}