package reuseport

import (
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"
)

// LoadOptions defines how the reuseport artifact should be loaded.
type LoadOptions struct {
	// CollectionOptions are forwarded to cilium/ebpf during load time.
	CollectionOptions *ciliumebpf.CollectionOptions

	// Spec allows the caller to provide a preloaded or prepatched CollectionSpec.
	// If nil, the generated loader is used directly.
	Spec *ciliumebpf.CollectionSpec
}

// Bundle exposes the generated program and maps in a stable shape for upper layers.
type Bundle struct {
	objects *reuseportObjects

	Selector  *ciliumebpf.Program
	SockMap   *ciliumebpf.Map
	ConfigMap *ciliumebpf.Map
}

// LoadSpec loads the generated CollectionSpec without loading it into the kernel yet.
//
// This is useful when you want to rewrite constants, replace maps,
// or inspect object layout before calling Load.
func LoadSpec() (*ciliumebpf.CollectionSpec, error) {
	spec, err := loadReuseport()
	if err != nil {
		return nil, fmt.Errorf("load reuseport spec: %w", err)
	}

	return spec, nil
}

// Load loads the reuseport eBPF artifact into the kernel.
func Load(opts *LoadOptions) (*Bundle, error) {
	var (
		objs           reuseportObjects
		collectionOpts *ciliumebpf.CollectionOptions
	)

	if opts != nil {
		collectionOpts = opts.CollectionOptions
	}

	if opts != nil && opts.Spec != nil {
		if err := opts.Spec.LoadAndAssign(&objs, collectionOpts); err != nil {
			return nil, fmt.Errorf("load reuseport spec and assign objects: %w", err)
		}
	} else {
		if err := loadReuseportObjects(&objs, collectionOpts); err != nil {
			return nil, fmt.Errorf("load reuseport objects: %w", err)
		}
	}

	return &Bundle{
		objects:   &objs,
		Selector:  objs.SelectReuseport,
		SockMap:   objs.SockMap,
		ConfigMap: objs.ConfigMap,
	}, nil
}

// Close releases the underlying eBPF resources.
func (b *Bundle) Close() error {
	if b == nil || b.objects == nil {
		return nil
	}

	return b.objects.Close()
}