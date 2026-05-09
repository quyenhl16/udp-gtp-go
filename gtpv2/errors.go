package gtpv2

import "errors"

var (
	// ErrPacketTooShort indicates that the input buffer is shorter than the required header size.
	ErrPacketTooShort = errors.New("gtpv2 packet too short")

	// ErrInvalidVersion indicates that the packet is not GTPv2.
	ErrInvalidVersion = errors.New("invalid gtpv2 version")
)