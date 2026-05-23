# 🛡️ Container Runtime Security Monitor

<div align="center">

### Production-grade Linux Runtime Threat Detection using eBPF + Go

Realtime container-aware runtime security monitoring for Linux workloads.

<p align="center">
  <img src="https://img.shields.io/badge/eBPF-Linux-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/Security-Runtime-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Kernel-Observability-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Containers-Docker%20%7C%20containerd-2496ED?style=for-the-badge" />
</p>

</div>

---

# ✨ Overview

`container-runtime-security-monitor` is a Linux runtime security monitoring system built using:

* eBPF
* Go
* Linux Tracepoints
* Ring Buffers
* Container Runtime Telemetry

The monitor hooks into the Linux kernel using eBPF and captures realtime process execution events from containers and host systems with extremely low overhead.

It provides runtime visibility into:

* shell execution
* network utility execution
* suspicious container activity
* runtime process telemetry
* container-aware security events

---

# 🚀 Features

* 🔍 execve syscall tracing
* 🐳 Docker/containerd visibility
* ⚡ eBPF ring buffer telemetry
* 🛡️ Runtime threat detection
* 📦 Container-aware process monitoring
* 🧠 Policy engine support
* 🌐 Network tool execution detection
* 🔥 Low-overhead kernel instrumentation
* 📟 Realtime event streaming

---

# 🏗️ Architecture

```text
+--------------------------------------------------+
|                  User Space                      |
|--------------------------------------------------|
|                                                  |
|  Go Runtime Monitor                              |
|  ├── Ring Buffer Reader                          |
|  ├── Policy Engine                               |
|  ├── Container Resolver                          |
|  └── Alert Engine                                |
|                                                  |
+------------------------▲-------------------------+
                         |
                         |
                 Ring Buffer Events
                         |
+------------------------▼-------------------------+
|                  Kernel Space                    |
|--------------------------------------------------|
|                                                  |
|  eBPF Tracepoint Program                         |
|  ├── sys_enter_execve Hook                       |
|  ├── Process Metadata Collection                 |
|  ├── Runtime Filtering                           |
|  └── Threat Detection Logic                      |
|                                                  |
+--------------------------------------------------+
```

---

# 🔬 Detection Capabilities

| Detection                    | Description                                 |
| ---------------------------- | ------------------------------------------- |
| `shell_execution`            | Detects `/bin/sh` and `/bin/bash` execution |
| `network_tool_execution`     | Detects `curl`, `wget`, `nc`                |
| `reverse_shell_detected`     | Detects suspicious netcat execution         |
| `container_exec`             | Detects container runtime process execution |
| `runtime_process_monitoring` | Monitors runtime process telemetry          |

---

# 📁 Project Structure

```bash
container-runtime-security-monitor/
│
├── ebpf/
│   ├── monitor.bpf.c
│   ├── monitor.bpf.o
│   └── vmlinux.h
│
├── internal/
│   ├── container/
│   │   └── resolver.go
│   │
│   └── policy/
│       └── policy.go
│
├── scripts/
│   └── run.sh
│
├── main.go
├── go.mod
├── go.sum
└── README.md
```

---

# ⚙️ Requirements

* Linux Kernel 5.x+
* clang
* bpftool
* Go 1.24+
* sudo/root access

---

# 🔧 Build Instructions

## 1️⃣ Generate Kernel Headers

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
```

---

## 2️⃣ Build eBPF Program

```bash
clang -O2 -g -target bpf \
  -c ebpf/monitor.bpf.c \
  -o ebpf/monitor.bpf.o
```

---

## 3️⃣ Install Go Dependencies

```bash
go mod tidy
```

---

# ▶️ Run

```bash
sudo go run main.go
```

---

# 🧪 Runtime Demo

## Terminal 1

Start the runtime monitor:

```bash
sudo go run main.go
```

---

## Terminal 2

Trigger suspicious runtime activity:

```bash
curl google.com

bash

nc google.com 80
```

---

# 📟 Example Output

```text
[EVENT] pid=1042 uid=1000 process=curl alert=network_tool_execution

[EVENT] pid=1055 uid=1000 process=bash alert=shell_execution

[EVENT] pid=1071 uid=1000 process=nc alert=reverse_shell_detected
```

---

# 🧠 Runtime Detection Logic

The eBPF program attaches to:

```text
tracepoint/syscalls/sys_enter_execve
```

Captured telemetry includes:

* PID
* UID
* process name
* executed binary
* runtime alert classification

Events are streamed from kernel space to user space using:

* eBPF Ring Buffers

---

# 🛡️ Security Use Cases

* Container Runtime Security
* Linux Threat Detection
* Cloud Workload Protection
* Kubernetes Runtime Visibility
* DevSecOps Monitoring
* Runtime Telemetry Collection
* Kernel Observability
* Container Threat Hunting

---

# 🔥 Technologies Used

| Technology        | Purpose                     |
| ----------------- | --------------------------- |
| eBPF              | Kernel instrumentation      |
| Go                | Userspace runtime monitor   |
| Linux Tracepoints | Syscall tracing             |
| Ring Buffers      | Event streaming             |
| Docker/containerd | Container runtime telemetry |
| libbpf            | eBPF integration            |

---

# 📈 Future Improvements

* Kubernetes namespace awareness
* Falco-style rules engine
* Prometheus metrics export
* JSON structured logging
* Process ancestry tracking
* Namespace correlation
* Network socket telemetry
* Container image correlation
* Runtime policy enforcement
* Grafana dashboards

---

# 📜 License

GPL-3.0 License

---

# 👨‍💻 Author

## Tejas Shinde

* Linux Systems Engineering
* eBPF & Kernel Instrumentation
* Runtime Security
* Distributed Systems
* Storage & Platform Engineering

GitHub:

```text
https://github.com/RoyalTejShinde1993
```

---

<div align="center">

### ⭐ If you like this project, consider starring the repository.

</div>
