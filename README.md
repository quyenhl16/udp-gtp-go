# udp-gtp-go

`udp-gtp-go` is a Go + eBPF Linux project for building high-performance UDP servers on a single IP:Port using `SO_REUSEPORT`, with traffic steering driven by an eBPF `SK_REUSEPORT` selector.

The current implementation is oriented around **GTPv2-C** traffic and demonstrates how to classify packets by **message type** and steer them into different socket pools, for example:

- **S11 pool**: 4 sockets
- **S10 pool**: 1 socket

The repository is designed as a reusable foundation rather than a one-off demo. The eBPF runtime is intentionally separated from the built-in UDP server so that other Go projects can import and reuse the eBPF module with their own socket-group implementation.

---

## Goals

This project aims to provide:

- a reusable **Go UDP server foundation**
- a reusable **Linux `SO_REUSEPORT` socket group**
- a modular **eBPF runtime framework**
- a clean pattern for **hook-specific eBPF modules**
- a practical example of **GTPv2-C-aware traffic steering**
- a codebase that can evolve into a reusable third-party library

---

## Key ideas

### 1. Single IP:Port, multiple UDP sockets

The server opens multiple UDP sockets bound to the same IP:Port using `SO_REUSEPORT`.

### 2. eBPF-based socket selection

Instead of relying only on the kernel default reuseport hashing, an eBPF `SK_REUSEPORT` program reads packet metadata and selects a socket from a target pool.

### 3. Traffic classification by GTPv2-C message type

For the current demo, packets are classified by **GTPv2-C message type** and mapped into:

- **S11 socket pool**
- **S10 socket pool**
- optional fallback behavior

### 4. Reusable eBPF integration model

The eBPF runtime is designed to be reusable outside the built-in UDP server.

The `ebpf/hooks/reuseport` module does not depend on the server package and does not require the repository's `reuseport.Group` type directly.

Instead, it depends on a small socket-group abstraction defined under `ebpf/contracts`.

This allows:

- the built-in server to use the module with `reuseport.Group`
- other Go projects to import the same eBPF module and provide their own socket-group implementation
- the eBPF layer to remain reusable and independent from higher-level server orchestration

### 5. Extensible architecture

The repository is intentionally structured so that future eBPF programs can be added without redesigning the current runtime model, for example:

- additional `SK_REUSEPORT` selectors
- XDP programs
- TC programs
- tracing programs
- cgroup-based socket policies

---

## Repository structure

```text
.
├── bpf/
│   ├── common/
│   │   └── common.h
│   └── reuseport/
│       └── selector.c
│
├── config/
│   ├── config.go
│   ├── default.go
│   ├── env.go
│   ├── load.go
│   ├── validate.go
│   └── doc.go
│
├── udp/
│   ├── doc.go
│   ├── types.go
│   ├── options.go
│   ├── errors.go
│   ├── conn.go
│   ├── socket_linux.go
│   └── readwrite.go
│
├── reuseport/
│   ├── doc.go
│   ├── options.go
│   ├── errors.go
│   ├── group.go
│   └── socket_linux.go
│
├── ebpf/
│   ├── doc.go
│   ├── core/
│   │   ├── doc.go
│   │   ├── errors.go
│   │   ├── module.go
│   │   ├── collection.go
│   │   └── registry.go
│   │
│   ├── contracts/
│   │   └── socket_group.go
│   │
│   ├── maps/
│   │   ├── doc.go
│   │   ├── array.go
│   │   └── sockarray.go
│   │
│   ├── hooks/
│   │   └── reuseport/
│   │       ├── doc.go
│   │       ├── config.go
│   │       ├── module.go
│   │       └── attach_linux.go
│   │
│   └── artifacts/
│       └── reuseport/
│           ├── doc.go
│           ├── gen.go
│           ├── load.go
│           ├── reuseport_bpfel.go
│           └── reuseport_bpfeb.go
│
├── server/
│   ├── doc.go
│   ├── types.go
│   ├── errors.go
│   ├── options.go
│   └── server.go
│
├── cmd/
│   └── demo/
│       └── main.go
│
├── tools/
│   └── tools.go
│
├── go.mod
└── README.md

```

## Development commands

```bash
# Generate eBPF bindings after changing files under bpf/
go generate ./...

# Build all packages
go build ./...

# Build the demo binary
go build -o bin/demo ./cmd/demo

# Run tests
go test ./...

# Run the demo directly without building a binary first
sudo go run ./cmd/demo

# Run the demo directly with a config file
sudo go run ./cmd/demo -config ./config.json

# Run the benchmark client
go run ./cmd/bench \
  -addr 127.0.0.1:2123 \
  -mode request_response \
  -workers 8 \
  -duration 10s
```
