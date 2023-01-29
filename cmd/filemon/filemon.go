package main

import (
	"fmt"
	"kubescape-ebpf/core/common"
	fileaccessmonitor "kubescape-ebpf/core/file-access-monitor"
	"os"
	"os/signal"
	"syscall"
)

type CommandFileActivityMonitorClient struct {
}

func (client *CommandFileActivityMonitorClient) Notify(event fileaccessmonitor.FileActivityEvent) {
	cid, _ := common.GetContainerIdForNsMntId(event.NsMntId)
	if cid != "" {
		fmt.Println("Cmd:", event.Comm, "File: ", event.File, " PID: ", event.Pid, " Container ID: ", cid)
	} else {
		fmt.Println("Cmd:", event.Comm, "File: ", event.File, " PID: ", event.Pid)
	}
}

func main() {
	// Create client
	client := CommandFileActivityMonitorClient{}

	// Create CreateFileActivityMonitor
	am := fileaccessmonitor.CreateFileActivityMonitor(&client)

	// Start
	am.Start()
	defer am.Stop()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
