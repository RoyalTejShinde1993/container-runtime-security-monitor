// ebpf/monitor.bpf.c

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[64];
    char alert[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *evt;

    const char *filename = (const char *)ctx->args[0];

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // =========================================================
    // PROCESS INFORMATION
    // =========================================================

    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_probe_read_user_str(
        evt->filename,
        sizeof(evt->filename),
        filename
    );

    // =========================================================
    // FILTER RUNTIME / DEVCONTAINER NOISE
    // =========================================================

    if (
    __builtin_memcmp(evt->comm, "sh", 2) == 0 ||
    __builtin_memcmp(evt->comm, "node", 4) == 0 ||
    __builtin_memcmp(evt->comm, "sleep", 5) == 0 ||
    __builtin_memcmp(evt->comm, "grep", 4) == 0 ||
    __builtin_memcmp(evt->comm, "ls", 2) == 0 ||
    __builtin_memcmp(evt->comm, "which", 5) == 0 ||
    __builtin_memcmp(evt->comm, "ps", 2) == 0 ||
    __builtin_memcmp(evt->comm, "top", 3) == 0 ||
    __builtin_memcmp(evt->comm, "cat", 3) == 0 ||
    __builtin_memcmp(evt->comm, "runc", 4) == 0 ||
    __builtin_memcmp(evt->comm, "containerd-sh", 13) == 0 ||
    __builtin_memcmp(evt->comm, ".NET TP Worker", 14) == 0 ||
    __builtin_memcmp(evt->comm, "cpuUsage.sh", 11) == 0 ||
    __builtin_memcmp(evt->comm, "auoms", 5) == 0 ||
    __builtin_memcmp(evt->comm, "apt-get", 7) == 0 ||
    __builtin_memcmp(evt->comm, "dpkg", 4) == 0 ||
    __builtin_memcmp(evt->comm, "packagekitd", 11) == 0 ||
    __builtin_memcmp(evt->comm, "cnf-update-db", 13) == 0 ||
    __builtin_memcmp(evt->comm, "(kagekitd)", 10) == 0 ||
    __builtin_memcmp(evt->comm, "(polkitd)", 9) == 0
    ) {

        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    // =========================================================
    // SECURITY DETECTIONS
    // =========================================================

    // Shell execution detection
    if (
        __builtin_memcmp(evt->filename, "/bin/sh", 7) == 0 ||
        __builtin_memcmp(evt->filename, "/bin/bash", 10) == 0
       ) {

        __builtin_memcpy(
            evt->alert,
            "shell_execution",
            16
        );

    // Network tool execution detection
    } else if (
        __builtin_memcmp(evt->comm, "curl", 4) == 0 ||
        __builtin_memcmp(evt->comm, "wget", 4) == 0 ||
        __builtin_memcmp(evt->comm, "nc", 2) == 0
    ) {

        __builtin_memcpy(
            evt->alert,
            "network_tool_execution",
            25
        );

    // Default
    } else {

        __builtin_memcpy(
            evt->alert,
            "normal",
            7
        );
    }

    // Submit event
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

