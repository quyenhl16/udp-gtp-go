package gtpv2

import "encoding/binary"

// DecodeHeader parses the fixed GTPv2-C header from the provided payload.
//
// The input is expected to start at the GTPv2-C header, not at the UDP header.
func DecodeHeader(b []byte) (Header, error) {
	if len(b) < 4 {
		return Header{}, ErrPacketTooShort
	}

	h := Header{
		Flags:       b[0],
		MessageType: b[1],
		Length:      binary.BigEndian.Uint16(b[2:4]),
	}

	if h.Version() != Version2 {
		return Header{}, ErrInvalidVersion
	}

	required := HeaderLengthWithoutTEID
	if h.HasTEID() {
		required = HeaderLengthWithTEID
	}

	if len(b) < required {
		return Header{}, ErrPacketTooShort
	}

	offset := 4

	if h.HasTEID() {
		h.TEID = binary.BigEndian.Uint32(b[offset : offset+4])
		offset += 4
	}

	h.Sequence = uint32(b[offset])<<16 | uint32(b[offset+1])<<8 | uint32(b[offset+2])
	h.Spare = b[offset+3]

	return h, nil
}

// MessageType returns the GTPv2-C message type without fully decoding the header.
func MessageType(b []byte) (uint8, error) {
	if len(b) < 2 {
		return 0, ErrPacketTooShort
	}
	return b[1], nil
}

// HasTEID reports whether the TEID flag is set in the provided packet.
func HasTEID(b []byte) (bool, error) {
	if len(b) < 1 {
		return false, ErrPacketTooShort
	}
	return b[0]&FlagTEID != 0, nil
}