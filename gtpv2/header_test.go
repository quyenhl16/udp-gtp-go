package gtpv2

import "testing"

func TestDecodeHeaderWithTEID(t *testing.T) {
	packet := []byte{
		0x48,       // Flags: version=2, T=1
		0x20,       // MessageType: 32
		0x00, 0x08, // Length
		0x11, 0x22, 0x33, 0x44, // TEID
		0x01, 0x02, 0x03, 0x00, // Sequence(3) + Spare
	}

	h, err := DecodeHeader(packet)
	if err != nil {
		t.Fatalf("DecodeHeader returned error: %v", err)
	}

	if got, want := h.Version(), uint8(2); got != want {
		t.Fatalf("Version() = %d, want %d", got, want)
	}

	if got, want := h.MessageType, uint8(0x20); got != want {
		t.Fatalf("MessageType = %d, want %d", got, want)
	}

	if !h.HasTEID() {
		t.Fatalf("HasTEID() = false, want true")
	}

	if got, want := h.TEID, uint32(0x11223344); got != want {
		t.Fatalf("TEID = %#x, want %#x", got, want)
	}

	if got, want := h.Sequence, uint32(0x010203); got != want {
		t.Fatalf("Sequence = %#x, want %#x", got, want)
	}

	if got, want := h.HeaderLength(), HeaderLengthWithTEID; got != want {
		t.Fatalf("HeaderLength() = %d, want %d", got, want)
	}
}

func TestDecodeHeaderWithoutTEID(t *testing.T) {
	packet := []byte{
		0x40,       // Flags: version=2, T=0
		0x02,       // MessageType
		0x00, 0x04, // Length
		0x01, 0x02, 0x03, 0x00, // Sequence(3) + Spare
	}

	h, err := DecodeHeader(packet)
	if err != nil {
		t.Fatalf("DecodeHeader returned error: %v", err)
	}

	if h.HasTEID() {
		t.Fatalf("HasTEID() = true, want false")
	}

	if got, want := h.Sequence, uint32(0x010203); got != want {
		t.Fatalf("Sequence = %#x, want %#x", got, want)
	}

	if got, want := h.HeaderLength(), HeaderLengthWithoutTEID; got != want {
		t.Fatalf("HeaderLength() = %d, want %d", got, want)
	}
}

func TestDecodeHeaderTooShort(t *testing.T) {
	packet := []byte{0x48, 0x20, 0x00}

	_, err := DecodeHeader(packet)
	if err == nil {
		t.Fatalf("DecodeHeader() error = nil, want non-nil")
	}
}

func TestDecodeHeaderInvalidVersion(t *testing.T) {
	packet := []byte{
		0x28,       // Version != 2
		0x20,
		0x00, 0x08,
		0x11, 0x22, 0x33, 0x44,
		0x01, 0x02, 0x03, 0x00,
	}

	_, err := DecodeHeader(packet)
	if err != ErrInvalidVersion {
		t.Fatalf("DecodeHeader() error = %v, want %v", err, ErrInvalidVersion)
	}
}

func TestMessageType(t *testing.T) {
	packet := []byte{0x48, 0x20}

	msgType, err := MessageType(packet)
	if err != nil {
		t.Fatalf("MessageType() returned error: %v", err)
	}

	if got, want := msgType, uint8(0x20); got != want {
		t.Fatalf("MessageType() = %d, want %d", got, want)
	}
}