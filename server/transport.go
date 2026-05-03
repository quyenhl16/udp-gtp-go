package server

import (
	"fmt"
	"net"

	rpsock "github.com/quyenhl16/udp-gtp-go/reuseport"
	"github.com/quyenhl16/udp-gtp-go/udp"
)

type socketSet interface {
	Conns() []*net.UDPConn
	LocalAddr() net.Addr
	Len() int
	Close() error
}

type singleSocketSet struct {
	conn *udp.UDPConn
}

func openSingleSocketSet(opts udp.Options) (*singleSocketSet, error) {
	conn, err := udp.Listen(opts)
	if err != nil {
		return nil, err
	}

	return &singleSocketSet{
		conn: conn,
	}, nil
}

func (s *singleSocketSet) Conns() []*net.UDPConn {
	if s == nil || s.conn == nil || s.conn.RawConn() == nil {
		return nil
	}

	return []*net.UDPConn{s.conn.RawConn()}
}

func (s *singleSocketSet) LocalAddr() net.Addr {
	if s == nil || s.conn == nil {
		return nil
	}

	return s.conn.LocalAddr()
}

func (s *singleSocketSet) Len() int {
	if s == nil || s.conn == nil {
		return 0
	}

	return 1
}

func (s *singleSocketSet) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}

	return s.conn.Close()
}

type reuseportSocketSet struct {
	group *rpsock.Group
}

func openReuseportSocketSet(opts rpsock.Options) (*reuseportSocketSet, error) {
	group, err := rpsock.Open(opts)
	if err != nil {
		return nil, err
	}

	return &reuseportSocketSet{
		group: group,
	}, nil
}

func (s *reuseportSocketSet) Conns() []*net.UDPConn {
	if s == nil || s.group == nil {
		return nil
	}

	return s.group.Conns()
}

func (s *reuseportSocketSet) LocalAddr() net.Addr {
	if s == nil || s.group == nil {
		return nil
	}

	return s.group.LocalAddr()
}

func (s *reuseportSocketSet) Len() int {
	if s == nil || s.group == nil {
		return 0
	}

	return s.group.Len()
}

func (s *reuseportSocketSet) Close() error {
	if s == nil || s.group == nil {
		return nil
	}

	return s.group.Close()
}

func (s *reuseportSocketSet) Group() *rpsock.Group {
	if s == nil {
		return nil
	}

	return s.group
}

func openSocketSet(cfg any, mode Mode) (socketSet, *rpsock.Group, error) {
	switch mode {
	case ModeSingle:
		appCfg, ok := cfg.(buildConfig)
		if !ok {
			return nil, nil, fmt.Errorf("invalid single socket config")
		}

		set, err := openSingleSocketSet(appCfg.udp)
		if err != nil {
			return nil, nil, err
		}

		return set, nil, nil

	case ModeReusePort:
		appCfg, ok := cfg.(buildConfig)
		if !ok {
			return nil, nil, fmt.Errorf("invalid reuseport socket config")
		}

		set, err := openReuseportSocketSet(appCfg.reuseport)
		if err != nil {
			return nil, nil, err
		}

		return set, set.Group(), nil

	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrUnknownMode, mode)
	}
}

type buildConfig struct {
	udp       udp.Options
	reuseport rpsock.Options
}