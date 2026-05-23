package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/RoyalTejShinde1993/container-runtime-security-monitor/internal/container"
	"github.com/RoyalTejShinde1993/container-runtime-security-monitor/internal/policy"
)

type Event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [64]byte
	Alert    [32]byte
}

func main() {

	// =========================================================
	// LOAD eBPF OBJECT
	// =========================================================

	spec, err := ebpf.LoadCollectionSpec("ebpf/monitor.bpf.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	objs := struct {
		TraceExecve *ebpf.Program `ebpf:"trace_execve"`
		Events      *ebpf.Map     `ebpf:"events"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// =========================================================
	// ATTACH TRACEPOINT
	// =========================================================

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		objs.TraceExecve,
		nil,
	)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// =========================================================
	// OPEN RING BUFFER
	// =========================================================

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf: %v", err)
	}
	defer reader.Close()

	fmt.Println("[+] container-runtime-security-monitor started")

	// =========================================================
	// HANDLE CTRL+C
	// =========================================================

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fmt.Println("\n[+] shutting down")
		reader.Close()
		os.Exit(0)
	}()

	// =========================================================
	// EVENT LOOP
	// =========================================================

	for {
		record, err := reader.Read()
		if err != nil {
			log.Printf("ringbuf read: %v", err)
			continue
		}

		var event Event

		if err := binary.Read(
			bytes.NewBuffer(record.RawSample),
			binary.LittleEndian,
			&event,
		); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}

		// Convert byte arrays to strings
		comm := string(bytes.Trim(event.Comm[:], "\x00"))
		filename := string(bytes.Trim(event.Filename[:], "\x00"))
		kernelAlert := string(bytes.Trim(event.Alert[:], "\x00"))

		// Resolve container info
		containerID := container.ResolveContainer(event.Pid)

		// Optional policy engine
		policyAlert := policy.Evaluate(comm)

		finalAlert := kernelAlert

		if policyAlert != "" && policyAlert != "normal" {
			finalAlert = policyAlert
		}

		// =====================================================
		// PRINT EVENT
		// =====================================================

		fmt.Printf(
			"[EVENT] pid=%d uid=%d container=%s process=%s file=%s alert=%s\n",
			event.Pid,
			event.Uid,
			containerID,
			comm,
			filename,
			finalAlert,
		)
	}
}
