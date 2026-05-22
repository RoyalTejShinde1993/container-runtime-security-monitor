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
)

type Event struct {
	Pid   uint32
	Uid   uint32
	Comm  [16]byte
	Alert [32]byte
}

func main() {

	spec, err := ebpf.LoadCollectionSpec("ebpf/monitor.bpf.o")
	if err != nil {
		log.Fatalf("loading spec failed: %v", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("loading collection failed: %v", err)
	}

	defer collection.Close()

	prog := collection.Programs["trace_execve"]

	if prog == nil {
		log.Fatal("trace_execve program not found")
	}

	tp, err := link.Tracepoint(
		"syscalls",
		"sys_enter_execve",
		prog,
		nil,
	)

	if err != nil {
		log.Fatalf("tracepoint attach failed: %v", err)
	}

	defer tp.Close()

	eventsMap := collection.Maps["events"]

	if eventsMap == nil {
		log.Fatal("events map not found")
	}

	rd, err := ringbuf.NewReader(eventsMap)

	if err != nil {
		log.Fatalf("ringbuf open failed: %v", err)
	}

	defer rd.Close()

	fmt.Println("[+] runtime security monitor started")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fmt.Println("\n[+] shutting down")
		rd.Close()
		os.Exit(0)
	}()

	for {
		record, err := rd.Read()

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

		fmt.Printf(
			"[EVENT] pid=%d uid=%d process=%s alert=%s\n",
			event.Pid,
			event.Uid,
			bytes.Trim(event.Comm[:], "\x00"),
			bytes.Trim(event.Alert[:], "\x00"),
		)
	}
}
