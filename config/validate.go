package config

import (
	"errors"
	"fmt"
	"strings"
)

func (c *AppConfig) Normalize() {
	if strings.TrimSpace(c.App.Name) == "" {
		c.App.Name = "udp-gtp-go"
	}

	if strings.TrimSpace(c.Listen.Network) == "" {
		c.Listen.Network = "udp"
	}

	if strings.TrimSpace(c.Listen.Host) == "" {
		c.Listen.Host = "0.0.0.0"
	}

	if c.Listen.Port == 0 {
		c.Listen.Port = 2152
	}

	if c.ReusePort.SocketCount == 0 {
		c.ReusePort.SocketCount = 5
	}

	if c.ReusePort.S11Weight == 0 {
		c.ReusePort.S11Weight = 4
	}

	if c.ReusePort.S10Weight == 0 {
		c.ReusePort.S10Weight = 1
	}

	if c.ReusePort.RecvBufferBytes <= 0 {
		c.ReusePort.RecvBufferBytes = 4 * 1024 * 1024
	}

	if c.ReusePort.SendBufferBytes <= 0 {
		c.ReusePort.SendBufferBytes = 4 * 1024 * 1024
	}

	if strings.TrimSpace(c.Metrics.Path) == "" {
		c.Metrics.Path = "/metrics"
	}

	if strings.TrimSpace(c.Metrics.Address) == "" {
		c.Metrics.Address = ":9090"
	}
}

func (c AppConfig) Validate() error {
	var errs []error

	switch c.Listen.Network {
	case "udp", "udp4", "udp6":
	default:
		errs = append(errs, fmt.Errorf("listen.network must be one of udp, udp4, udp6: got %q", c.Listen.Network))
	}

	if c.Listen.Port < 1 || c.Listen.Port > 65535 {
		errs = append(errs, fmt.Errorf("listen.port must be between 1 and 65535: got %d", c.Listen.Port))
	}

	if c.ReusePort.Enabled {
		if c.ReusePort.SocketCount <= 0 {
			errs = append(errs, fmt.Errorf("reuseport.socket_count must be > 0: got %d", c.ReusePort.SocketCount))
		}
		if c.ReusePort.S11Weight <= 0 {
			errs = append(errs, fmt.Errorf("reuseport.s11_weight must be > 0: got %d", c.ReusePort.S11Weight))
		}
		if c.ReusePort.S10Weight <= 0 {
			errs = append(errs, fmt.Errorf("reuseport.s10_weight must be > 0: got %d", c.ReusePort.S10Weight))
		}

		expected := c.ReusePort.S11Weight + c.ReusePort.S10Weight
		if c.ReusePort.SocketCount != expected {
			errs = append(errs, fmt.Errorf(
				"reuseport.socket_count must equal s11_weight + s10_weight: got socket_count=%d, expected=%d",
				c.ReusePort.SocketCount, expected,
			))
		}
	}

	if c.ReusePort.RecvBufferBytes < 0 {
		errs = append(errs, fmt.Errorf("reuseport.recv_buffer_bytes must be >= 0: got %d", c.ReusePort.RecvBufferBytes))
	}

	if c.ReusePort.SendBufferBytes < 0 {
		errs = append(errs, fmt.Errorf("reuseport.send_buffer_bytes must be >= 0: got %d", c.ReusePort.SendBufferBytes))
	}

	if c.EBPF.Enabled {
		if c.EBPF.S11MessageType == c.EBPF.S10MessageType {
			errs = append(errs, fmt.Errorf(
				"ebpf.s11_message_type and ebpf.s10_message_type must be different: both are %d",
				c.EBPF.S11MessageType,
			))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}