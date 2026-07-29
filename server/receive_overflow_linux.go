//go:build linux

package server

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

func enableReceiveOverflow(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 1)
	}); err != nil {
		return fmt.Errorf("socket control: %w", err)
	}
	return controlErr
}

func receiveControlBufferSize() int {
	return unix.CmsgSpace(4)
}

func readUDPWithOverflow(conn *net.UDPConn, payload, oob []byte) (int, *net.UDPAddr, uint32, bool, error) {
	n, oobn, _, addr, err := conn.ReadMsgUDP(payload, oob)
	if err != nil {
		return 0, nil, 0, false, err
	}

	messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	if parseErr != nil {
		return 0, nil, 0, false, fmt.Errorf("parse socket control message: %w", parseErr)
	}
	for _, message := range messages {
		if message.Header.Level == unix.SOL_SOCKET &&
			message.Header.Type == unix.SO_RXQ_OVFL && len(message.Data) >= 4 {
			return n, addr, binary.NativeEndian.Uint32(message.Data[:4]), true, nil
		}
	}

	return n, addr, 0, false, nil
}
