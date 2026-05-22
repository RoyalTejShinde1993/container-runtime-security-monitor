#!/bin/bash
set -e

echo "[+] building eBPF object"
clang -O2 -g -target bpf -c ebpf/monitor.bpf.c -o ebpf/monitor.bpf.o

echo "[+] building Go agent"
go build -o runtime-agent ./cmd/agent

echo "[+] done"
