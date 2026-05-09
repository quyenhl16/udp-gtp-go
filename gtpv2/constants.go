package gtpv2

const (
	// Version2 is the expected GTPv2 version value.
	Version2 = 2
)

const (
	// FlagVersionMask extracts the version bits from the flags octet.
	FlagVersionMask = 0xE0

	// FlagVersionShift is the bit shift used to decode the version.
	FlagVersionShift = 5

	// FlagPiggybacking indicates that a piggybacked message is present.
	FlagPiggybacking = 0x10

	// FlagTEID indicates that the header contains a TEID field.
	FlagTEID = 0x08

	// FlagMessagePriority indicates that the message priority flag is set.
	FlagMessagePriority = 0x04
)

const (
	// HeaderLengthWithoutTEID is the minimum GTPv2-C header length without TEID.
	HeaderLengthWithoutTEID = 8

	// HeaderLengthWithTEID is the minimum GTPv2-C header length with TEID.
	HeaderLengthWithTEID = 12
)

const (
	// Common GTPv2-C message types used frequently in practice.
	MsgTypeEchoRequest          uint8 = 1
	MsgTypeEchoResponse         uint8 = 2
	MsgTypeCreateSessionRequest uint8 = 32
	MsgTypeCreateSessionResponse uint8 = 33
	MsgTypeModifyBearerRequest  uint8 = 34
	MsgTypeModifyBearerResponse uint8 = 35
	MsgTypeDeleteSessionRequest uint8 = 36
	MsgTypeDeleteSessionResponse uint8 = 37
)