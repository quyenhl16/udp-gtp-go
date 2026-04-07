package reuseport

//go:generate go tool bpf2go -tags linux -cc clang -cflags "-O2 -g -Wall -Werror" -type reuseport_config reuseport ../../../bpf/reuseport/selector.c -- -I../../../bpf -I../../../bpf/common