package config

import "testing"

func TestValidateAllowsZeroSizedReuseportPool(t *testing.T) {
	cfg := Default()
	cfg.ReusePort.SocketCount = 8
	cfg.ReusePort.S11Weight = 8
	cfg.ReusePort.S10Weight = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNormalizeKeepsExplicitZeroSizedReuseportPool(t *testing.T) {
	cfg := Default()
	cfg.ReusePort.SocketCount = 8
	cfg.ReusePort.S11Weight = 8
	cfg.ReusePort.S10Weight = 0

	cfg.Normalize()

	if cfg.ReusePort.S11Weight != 8 || cfg.ReusePort.S10Weight != 0 {
		t.Fatalf("weights after Normalize() = (%d, %d), want (8, 0)", cfg.ReusePort.S11Weight, cfg.ReusePort.S10Weight)
	}
}
