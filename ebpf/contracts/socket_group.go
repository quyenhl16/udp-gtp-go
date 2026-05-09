package contracts

// SocketGroup abstracts a group of sockets that can be used by
// an eBPF reuseport module without depending on a concrete implementation.
type SocketGroup interface {
	// FD returns the socket file descriptor at the given index.
	FD(index int) (int, error)

	// FDs returns all socket file descriptors in the group.
	FDs() []int
}