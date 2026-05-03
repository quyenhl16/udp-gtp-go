package reuseport

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.19.0 -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -type reuseport_config reuseport ../../../bpf/reuseport/selector.c -- -I../../../bpf -I../../../bpf/common