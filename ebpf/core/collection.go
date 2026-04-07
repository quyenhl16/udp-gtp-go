package core

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// Collection is a lightweight runtime registry of loaded programs and maps.
type Collection struct {
	programs map[string]*ciliumebpf.Program
	maps     map[string]*ciliumebpf.Map
}

// NewCollection creates an empty Collection.
func NewCollection() *Collection {
	return &Collection{
		programs: make(map[string]*ciliumebpf.Program),
		maps:     make(map[string]*ciliumebpf.Map),
	}
}

// AddProgram stores a program under a logical name.
func (c *Collection) AddProgram(name string, prog *ciliumebpf.Program) {
	if c == nil || prog == nil {
		return
	}
	c.programs[name] = prog
}

// AddMap stores a map under a logical name.
func (c *Collection) AddMap(name string, m *ciliumebpf.Map) {
	if c == nil || m == nil {
		return
	}
	c.maps[name] = m
}

// Program returns a program by name.
func (c *Collection) Program(name string) (*ciliumebpf.Program, error) {
	if c == nil {
		return nil, ErrNilCollection
	}

	prog, ok := c.programs[name]
	if !ok || prog == nil {
		return nil, fmt.Errorf("%w: %s", ErrProgramNotFound, name)
	}

	return prog, nil
}

// Map returns a map by name.
func (c *Collection) Map(name string) (*ciliumebpf.Map, error) {
	if c == nil {
		return nil, ErrNilCollection
	}

	m, ok := c.maps[name]
	if !ok || m == nil {
		return nil, fmt.Errorf("%w: %s", ErrMapNotFound, name)
	}

	return m, nil
}

// Close closes all stored programs and maps.
func (c *Collection) Close() error {
	if c == nil {
		return nil
	}

	var firstErr error

	for _, prog := range c.programs {
		if prog == nil {
			continue
		}
		if err := prog.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	for _, m := range c.maps {
		if m == nil {
			continue
		}
		if err := m.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}