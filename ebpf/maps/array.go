package maps

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// UpdateArrayValue updates a single key in an ARRAY-like map.
func UpdateArrayValue(m *ciliumebpf.Map, key uint32, value any) error {
	if m == nil {
		return fmt.Errorf("ebpf map is nil")
	}

	if err := m.Update(&key, value, ciliumebpf.UpdateAny); err != nil {
		return fmt.Errorf("update array map key=%d: %w", key, err)
	}

	return nil
}