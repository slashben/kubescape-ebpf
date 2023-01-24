package common

import (
	"github.com/cilium/ebpf/rlimit"
	"log"
)

func init() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

// Global variable to store module names
var ModuleNames []string

func RegisterPart(name string) {
	ModuleNames = append(ModuleNames, name)
}
