package benchmark

import "testing"

func TestNextTEIDCyclesRange(t *testing.T) {
	tests := []struct {
		name     string
		base     uint32
		count    uint32
		packetID uint64
		want     uint32
	}{
		{name: "single count", base: 10, count: 1, packetID: 5, want: 10},
		{name: "zero count defaults to base", base: 10, count: 0, packetID: 5, want: 10},
		{name: "first packet", base: 10, count: 3, packetID: 1, want: 10},
		{name: "next packet", base: 10, count: 3, packetID: 2, want: 11},
		{name: "wrap", base: 10, count: 3, packetID: 4, want: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextTEID(tt.base, tt.count, tt.packetID)
			if got != tt.want {
				t.Fatalf("nextTEID() = %d, want %d", got, tt.want)
			}
		})
	}
}
