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
	Pid  uint32
	Tgid uint32
	Uid  uint32
	Comm [16]byte
}

func main() {

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

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf: %v", err)
	}
	defer reader.Close()

	fmt.Println("[+] container-runtime-security-monitor started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fmt.Println("\n[+] shutting down")
		reader.Close()
		os.Exit(0)
	}()

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
			continue
		}

		comm := string(bytes.Trim(event.Comm[:], "\x00"))

		containerID := container.ResolveContainer(event.Tgid)

		alert := policy.Evaluate(comm)

		fmt.Printf(
			"[EVENT] pid=%d uid=%d container=%s process=%s alert=%s\n",
			event.Pid,
			event.Uid,
			containerID,
			comm,
			alert,
		)
	}
}
