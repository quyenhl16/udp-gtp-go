package reuseport

import "errors"

var (
	// ErrInvalidSocketCount indicates that the socket count is invalid.
	ErrInvalidSocketCount = errors.New("invalid socket count")

	// ErrEmptyGroup indicates that the socket group is empty.
	ErrEmptyGroup = errors.New("empty reuseport group")

	// ErrIndexOutOfRange indicates that the socket index is invalid.
	ErrIndexOutOfRange = errors.New("socket index out of range")
)