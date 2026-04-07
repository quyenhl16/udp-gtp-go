# udp-gtp-go

`udp-gtp-go` is a Go + eBPF Linux project for building high-performance UDP servers on a single IP:Port using `SO_REUSEPORT`, with traffic steering driven by an eBPF `SK_REUSEPORT` selector.

The current implementation is oriented around **GTPv2-C** traffic and demonstrates how to classify packets by **message type** and steer them into different socket pools, for example:

- **S11 pool**: 4 sockets
- **S10 pool**: 1 socket

The project is designed with an extensible architecture so that additional eBPF programs, hooks, and packet processing modules can be added later without redesigning the core.

---

## Goals

This project aims to provide:

- A reusable **Go UDP server foundation**
- A reusable **Linux `SO_REUSEPORT` socket group**
- A modular **eBPF runtime framework**
- A clean pattern for **hook-specific eBPF modules**
- A practical example of **GTPv2-C-aware traffic steering**
- A codebase that can evolve into a reusable third-party library

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

### 4. Extensible eBPF architecture
The repository is intentionally structured so that future eBPF programs can be added easily, for example:

- additional `SK_REUSEPORT` selectors
- XDP programs
- TC programs
- tracing programs
- cgroup-based socket policies

---

# Repository structure

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
├── tools/
│   └── tools.go
│
├── go.mod
└── README.md