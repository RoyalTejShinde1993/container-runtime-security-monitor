# container-runtime-security-monitor

Production-level Linux container runtime security monitor using:
- eBPF
- Go
- libbpf
- tracepoints
- ring buffers
- container runtime detection

## Features

- execve syscall tracing
- container-aware runtime telemetry
- process monitoring
- policy engine
- runtime threat alerts
- Docker/containerd visibility

---

# Build & Run

```bash
chmod +x scripts/run.sh

sudo ./scripts/run.sh
```

---

# Manual Build

## Build eBPF

```bash
clang -O2 -g -target bpf \
  -c ebpf/monitor.bpf.c \
  -o ebpf/monitor.bpf.o
```

## Download Dependencies

```bash
go mod tidy
```

## Build Agent

```bash
go build -o container-runtime-security-monitor ./cmd/agent
```

## Mount tracing filesystems

```bash
sudo mount -t tracefs nodev /sys/kernel/tracing
sudo mount -t debugfs nodev /sys/kernel/debug
```

## Run

```bash
sudo ./container-runtime-security-monitor
```
