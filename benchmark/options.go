package benchmark

import (
	"fmt"
	"time"

	"github.com/quyenhl16/udp-gtp-go/gtpv2"
)

// Options defines the benchmark runtime configuration.
type Options struct {
	TargetAddr string

	Workers int

	// Duration controls how long the benchmark should run.
	// If both Duration and TotalPackets are set, the benchmark stops when either limit is hit.
	Duration time.Duration

	// TotalPackets limits the total number of packets to send across all workers.
	// If zero, the benchmark is duration-based.
	TotalPackets uint64

	Mode Mode

	// PayloadSize is the number of bytes after the fixed GTPv2-C header.
	PayloadSize int

	// ReadTimeout is used only in request-response mode.
	ReadTimeout time.Duration

	// WriteTimeout is applied before each write when non-zero.
	WriteTimeout time.Duration

	// Traffic defines the weighted messageType mix.
	Traffic []TrafficClass

	// BaseTEID and BaseSequence are used to generate synthetic GTPv2-C packets.
	BaseTEID     uint32
	BaseSequence uint32

	// SingleFlow forces all benchmark workers to share one UDP socket.
	// This is useful for testing reuseport behavior under one hot source flow.
	SingleFlow bool
}

// DefaultOptions returns a sensible benchmark configuration.
func DefaultOptions() Options {
	return Options{
		TargetAddr:   "127.0.0.1:2123",
		Workers:      1,
		Duration:     10 * time.Second,
		Mode:         ModeRequestResponse,
		PayloadSize:  0,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
		Traffic: []TrafficClass{
			{
				Name:        "S11",
				MessageType: gtpv2.MsgTypeCreateSessionRequest,
				Weight:      4,
			},
			{
				Name:        "S10",
				MessageType: 128,
				Weight:      1,
			},
		},
		BaseTEID:     1,
		BaseSequence: 1,
	}
}

// Normalize applies defaults to missing fields.
func (o *Options) Normalize() {
	def := DefaultOptions()

	if o.TargetAddr == "" {
		o.TargetAddr = def.TargetAddr
	}
	if o.Workers <= 0 {
		o.Workers = def.Workers
	}
	if o.Duration < 0 {
		o.Duration = 0
	}
	if o.Mode == "" {
		o.Mode = def.Mode
	}
	if o.PayloadSize < 0 {
		o.PayloadSize = 0
	}
	if o.ReadTimeout < 0 {
		o.ReadTimeout = 0
	}
	if o.WriteTimeout < 0 {
		o.WriteTimeout = 0
	}
	if len(o.Traffic) == 0 {
		o.Traffic = def.Traffic
	}
	if o.BaseTEID == 0 {
		o.BaseTEID = def.BaseTEID
	}
	if o.BaseSequence == 0 {
		o.BaseSequence = def.BaseSequence
	}
	if o.Duration == 0 && o.TotalPackets == 0 {
		o.Duration = def.Duration
	}
}

// Validate validates benchmark options.
func (o Options) Validate() error {
	if o.TargetAddr == "" {
		return fmt.Errorf("benchmark target address is empty")
	}

	switch o.Mode {
	case ModeFireAndForget, ModeRequestResponse:
	default:
		return fmt.Errorf("invalid benchmark mode: %q", o.Mode)
	}

	if o.Workers <= 0 {
		return fmt.Errorf("workers must be > 0: got %d", o.Workers)
	}

	if o.PayloadSize < 0 {
		return fmt.Errorf("payload_size must be >= 0: got %d", o.PayloadSize)
	}

	if len(o.Traffic) == 0 {
		return fmt.Errorf("traffic mix is empty")
	}

	totalWeight := 0
	for i, tc := range o.Traffic {
		if tc.Weight < 0 {
			return fmt.Errorf("traffic[%d].weight must be >= 0: got %d", i, tc.Weight)
		}
		totalWeight += tc.Weight
	}

	if totalWeight <= 0 {
		return fmt.Errorf("traffic total weight must be > 0")
	}

	if o.SingleFlow && o.Mode != ModeFireAndForget {
		return fmt.Errorf("single_flow is currently supported only in fire_and_forget mode")
	}

	return nil
}
