//go:build !linux

package server

import "net"

func enableReceiveOverflow(conn *net.UDPConn) error {
	return nil
}

func receiveControlBufferSize() int {
	return 0
}

func readUDPWithOverflow(conn *net.UDPConn, payload, oob []byte) (int, *net.UDPAddr, uint32, bool, error) {
	n, addr, err := conn.ReadFromUDP(payload)
	return n, addr, 0, false, err
}
