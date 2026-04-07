// Package main wires together UDP socket handling and eBPF-based reuseport
// selection for this project.
//
// Project layout:
//   - config: central application config (defaults, env overrides, file loading, validation)
//   - udp: low-level UDP socket open/read/write primitives
//   - reuseport: SO_REUSEPORT socket group lifecycle and FD exposure
//   - ebpf/core: generic module/registry abstractions for eBPF runtime
//   - ebpf/maps: typed helpers for common eBPF map operations
//   - ebpf/artifacts/reuseport: generated bindings + loading helpers for reuseport eBPF program
//   - ebpf/hooks/reuseport: runtime adapter to populate maps and attach reuseport program
//   - bpf/common: shared C headers/macros used by eBPF C sources
//   - bpf/reuseport: sk_reuseport selector implementation in C
//
// Design intent:
//   - keep UDP I/O, socket orchestration, and eBPF logic separated
//   - make hook-specific code isolated under ebpf/hooks/*
//   - keep generated artifact code separate from orchestration/runtime code
package main
