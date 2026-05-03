package server

// Package server wires config, reuseport sockets, eBPF selector,
// packet readers, and handler execution into a runnable UDP server.