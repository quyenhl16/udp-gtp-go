package benchmark

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"
)

type trafficPicker struct {
	classes []TrafficClass
	total   int
	rng     *rand.Rand
}

func newTrafficPicker(classes []TrafficClass, seed int64) (*trafficPicker, error) {
	if len(classes) == 0 {
		return nil, fmt.Errorf("traffic classes are empty")
	}

	total := 0
	active := make([]TrafficClass, 0, len(classes))
	for _, tc := range classes {
		if tc.Weight < 0 {
			return nil, fmt.Errorf("invalid traffic weight for messageType=%d", tc.MessageType)
		}
		if tc.Weight == 0 {
			continue
		}
		total += tc.Weight
		active = append(active, tc)
	}

	if total <= 0 {
		return nil, fmt.Errorf("traffic total weight must be > 0")
	}

	return &trafficPicker{
		classes: active,
		total:   total,
		rng:     rand.New(rand.NewSource(seed)),
	}, nil
}

func (p *trafficPicker) Next() TrafficClass {
	if len(p.classes) == 1 {
		return p.classes[0]
	}

	n := p.rng.Intn(p.total)
	acc := 0

	for _, tc := range p.classes {
		acc += tc.Weight
		if n < acc {
			return tc
		}
	}

	return p.classes[len(p.classes)-1]
}

// BuildGTPv2Message builds a synthetic GTPv2-C packet with TEID.
func BuildGTPv2Message(messageType uint8, teid uint32, sequence uint32, payloadSize int) []byte {
	if payloadSize < 0 {
		payloadSize = 0
	}

	// Flags: Version=2, T=1.
	packet := make([]byte, 12+payloadSize)
	packet[0] = 0x48
	packet[1] = messageType

	// GTPv2-C length excludes the first 4 bytes.
	binary.BigEndian.PutUint16(packet[2:4], uint16(8+payloadSize))
	binary.BigEndian.PutUint32(packet[4:8], teid)

	packet[8] = byte(sequence >> 16)
	packet[9] = byte(sequence >> 8)
	packet[10] = byte(sequence)
	packet[11] = 0

	return packet
}

func defaultSeed(workerIndex int) int64 {
	return time.Now().UnixNano() + int64(workerIndex*1000003)
}
