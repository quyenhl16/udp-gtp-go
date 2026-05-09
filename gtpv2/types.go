package gtpv2

// Header represents the parsed fixed GTPv2-C header fields.
type Header struct {
	Flags       uint8
	MessageType uint8
	Length      uint16

	TEID     uint32
	Sequence uint32
	Spare    uint8
}

// Version returns the GTP version extracted from the flags octet.
func (h Header) Version() uint8 {
	return (h.Flags & FlagVersionMask) >> FlagVersionShift
}

// HasTEID returns whether the header carries a TEID field.
func (h Header) HasTEID() bool {
	return h.Flags&FlagTEID != 0
}

// HasPiggybacking returns whether the piggybacking flag is set.
func (h Header) HasPiggybacking() bool {
	return h.Flags&FlagPiggybacking != 0
}

// HasMessagePriority returns whether the message priority flag is set.
func (h Header) HasMessagePriority() bool {
	return h.Flags&FlagMessagePriority != 0
}

// HeaderLength returns the parsed fixed header length in bytes.
func (h Header) HeaderLength() int {
	if h.HasTEID() {
		return HeaderLengthWithTEID
	}
	return HeaderLengthWithoutTEID
}