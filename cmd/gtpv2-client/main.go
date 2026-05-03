package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const (
	// GTPv2-C version 2 without piggybacking.
	gtpv2VersionFlags = 0x40

	// TEID flag in the first octet of the GTPv2-C header.
	gtpv2TEIDFlag = 0x08

	// Minimum GTPv2-C header length without TEID.
	gtpv2HeaderLenNoTEID = 8

	// Minimum GTPv2-C header length with TEID.
	gtpv2HeaderLenWithTEID = 12
)

type sendMode string

const (
	modeS11       sendMode = "s11"
	modeS10       sendMode = "s10"
	modeAlternate sendMode = "alternate"
	modeRatio     sendMode = "ratio"
)

type config struct {
	ServerAddr   string
	LocalAddr    string
	Count        int
	Interval     time.Duration
	Timeout      time.Duration
	Mode         sendMode
	S11Message   uint
	S10Message   uint
	S11Weight    int
	S10Weight    int
	UseTEID      bool
	TEID         uint
	SequenceBase uint
	Payload      string
	WaitReply    bool
	HexPayload   bool
}

func main() {
	cfg := parseFlags()

	if err := run(cfg); err != nil {
		log.Fatalf("client failed: %v", err)
	}
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.ServerAddr, "addr", "127.0.0.1:2123", "UDP server address")
	flag.StringVar(&cfg.LocalAddr, "local", "", "Optional local UDP address, for example 0.0.0.0:0")
	flag.IntVar(&cfg.Count, "count", 20, "Number of packets to send")
	flag.DurationVar(&cfg.Interval, "interval", 300*time.Millisecond, "Delay between packets")
	flag.DurationVar(&cfg.Timeout, "timeout", 2*time.Second, "Read timeout when waiting for reply")
	flag.StringVar((*string)(&cfg.Mode), "mode", string(modeRatio), "Send mode: s11|s10|alternate|ratio")

	flag.UintVar(&cfg.S11Message, "s11-msg", 32, "Message type used for S11 traffic")
	flag.UintVar(&cfg.S10Message, "s10-msg", 128, "Message type used for S10 traffic")
	flag.IntVar(&cfg.S11Weight, "s11-weight", 4, "Weight used in ratio mode for S11")
	flag.IntVar(&cfg.S10Weight, "s10-weight", 1, "Weight used in ratio mode for S10")

	flag.BoolVar(&cfg.UseTEID, "teid-enabled", false, "Include TEID in GTPv2-C header")
	flag.UintVar(&cfg.TEID, "teid", 1, "TEID value when TEID is enabled")
	flag.UintVar(&cfg.SequenceBase, "seq", 1, "Starting sequence number")
	flag.StringVar(&cfg.Payload, "payload", "hello-gtpv2", "Payload as plain text or hex string when -payload-hex is set")
	flag.BoolVar(&cfg.HexPayload, "payload-hex", false, "Interpret payload as hex string")
	flag.BoolVar(&cfg.WaitReply, "wait-reply", true, "Wait for server reply after each send")

	flag.Parse()

	return cfg
}

func run(cfg config) error {
	if cfg.Count <= 0 {
		return fmt.Errorf("count must be > 0")
	}
	if cfg.S11Weight <= 0 {
		return fmt.Errorf("s11-weight must be > 0")
	}
	if cfg.S10Weight <= 0 {
		return fmt.Errorf("s10-weight must be > 0")
	}

	payload, err := parsePayload(cfg.Payload, cfg.HexPayload)
	if err != nil {
		return fmt.Errorf("parse payload: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return fmt.Errorf("resolve server address: %w", err)
	}

	var localAddr *net.UDPAddr
	if strings.TrimSpace(cfg.LocalAddr) != "" {
		localAddr, err = net.ResolveUDPAddr("udp", cfg.LocalAddr)
		if err != nil {
			return fmt.Errorf("resolve local address: %w", err)
		}
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		return fmt.Errorf("dial udp: %w", err)
	}
	defer conn.Close()

	log.Printf("client started: local=%s remote=%s mode=%s count=%d",
		conn.LocalAddr().String(),
		conn.RemoteAddr().String(),
		cfg.Mode,
		cfg.Count,
	)

	replyBuf := make([]byte, 2048)

	for i := 0; i < cfg.Count; i++ {
		msgType := chooseMessageType(cfg, i)
		seq := uint32(cfg.SequenceBase) + uint32(i)

		packet, err := buildGTPv2Message(
			uint8(msgType),
			payload,
			cfg.UseTEID,
			uint32(cfg.TEID),
			seq,
		)
		if err != nil {
			return fmt.Errorf("build gtpv2 packet %d: %w", i, err)
		}

		n, err := conn.Write(packet)
		if err != nil {
			return fmt.Errorf("write packet %d: %w", i, err)
		}

		log.Printf(
			"sent packet[%d]: bytes=%d msgType=%d seq=%d teidEnabled=%v teid=%d",
			i,
			n,
			msgType,
			seq,
			cfg.UseTEID,
			cfg.TEID,
		)

		if cfg.WaitReply {
			if err := conn.SetReadDeadline(time.Now().Add(cfg.Timeout)); err != nil {
				return fmt.Errorf("set read deadline: %w", err)
			}

			rn, err := conn.Read(replyBuf)
			if err != nil {
				log.Printf("reply packet[%d]: read error: %v", i, err)
			} else {
				log.Printf("reply packet[%d]: %q (%d bytes)", i, string(replyBuf[:rn]), rn)
			}
		}

		if i != cfg.Count-1 && cfg.Interval > 0 {
			time.Sleep(cfg.Interval)
		}
	}

	log.Printf("client finished")
	return nil
}

func chooseMessageType(cfg config, index int) uint {
	switch cfg.Mode {
	case modeS11:
		return cfg.S11Message
	case modeS10:
		return cfg.S10Message
	case modeAlternate:
		if index%2 == 0 {
			return cfg.S11Message
		}
		return cfg.S10Message
	case modeRatio:
		window := cfg.S11Weight + cfg.S10Weight
		slot := index % window
		if slot < cfg.S11Weight {
			return cfg.S11Message
		}
		return cfg.S10Message
	default:
		return cfg.S11Message
	}
}

func buildGTPv2Message(messageType uint8, payload []byte, useTEID bool, teid uint32, sequence uint32) ([]byte, error) {
	headerLen := gtpv2HeaderLenNoTEID
	flags := byte(gtpv2VersionFlags)

	if useTEID {
		headerLen = gtpv2HeaderLenWithTEID
		flags |= gtpv2TEIDFlag
	}

	totalLen := headerLen + len(payload)
	if totalLen > 0xFFFF+4 {
		return nil, fmt.Errorf("packet too large")
	}

	// The GTPv2-C Length field is relative to the first 4 octets.
	gtpLength := uint16(totalLen - 4)

	buf := make([]byte, totalLen)
	buf[0] = flags
	buf[1] = messageType
	binary.BigEndian.PutUint16(buf[2:4], gtpLength)

	if useTEID {
		binary.BigEndian.PutUint32(buf[4:8], teid)
		putUint24(buf[8:11], sequence)
		buf[11] = 0
		copy(buf[12:], payload)
		return buf, nil
	}

	putUint24(buf[4:7], sequence)
	buf[7] = 0
	copy(buf[8:], payload)

	return buf, nil
}

func putUint24(dst []byte, value uint32) {
	if len(dst) < 3 {
		return
	}

	dst[0] = byte((value >> 16) & 0xFF)
	dst[1] = byte((value >> 8) & 0xFF)
	dst[2] = byte(value & 0xFF)
}

func parsePayload(s string, isHex bool) ([]byte, error) {
	if !isHex {
		return []byte(s), nil
	}

	clean := strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	clean = strings.TrimPrefix(clean, "0x")
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("hex payload must have even length")
	}

	data, err := hex.DecodeString(clean)
	if err != nil {
		return nil, err
	}

	return data, nil
}