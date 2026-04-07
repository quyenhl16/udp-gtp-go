package maps

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// SyncSockArray populates a socket array map using the provided socket file descriptors.
func SyncSockArray(m *ciliumebpf.Map, fds []int) error {
	if m == nil {
		return fmt.Errorf("ebpf map is nil")
	}

	for i, fd := range fds {
		key := uint32(i)
		value := uint32(fd)

		if err := m.Update(&key, &value, ciliumebpf.UpdateAny); err != nil {
			return fmt.Errorf("update sockarray[%d]: %w", i, err)
		}
	}

	return nil
}