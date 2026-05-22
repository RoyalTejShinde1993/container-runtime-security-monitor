#!/bin/bash

set -e

echo "[+] Installing dependencies"

sudo apt update

sudo apt install -y \
    clang \
    llvm \
    libbpf-dev \
    build-essential \
    gcc-multilib \
    pkg-config \
    golang-go \
    make \
    git \
    linux-tools-common \
    linux-tools-generic

echo "[+] Mounting tracefs/debugfs"

sudo mount -t tracefs nodev /sys/kernel/tracing || true
sudo mount -t debugfs nodev /sys/kernel/debug || true

echo "[+] Building eBPF"

clang -O2 -g -target bpf \
  -c ebpf/monitor.bpf.c \
  -o ebpf/monitor.bpf.o

echo "[+] Downloading Go modules"

go mod tidy

echo "[+] Building Runtime Monitor"

go build -o container-runtime-security-monitor ./cmd/agent

echo "[+] Starting Runtime Monitor"

sudo ./container-runtime-security-monitor
