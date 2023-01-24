package fileaccessmonitor

import (
	"fmt"
	"os"
	"testing"
)

type TestFileActivityMonitorClient struct {
	listOfFiles []string
}

func (client *TestFileActivityMonitorClient) Notify(event FileActivityEvent) {
	client.listOfFiles = append(client.listOfFiles, event.File)
}

func TestBpf(t *testing.T) {
	// Create client
	client := TestFileActivityMonitorClient{}

	// Create CreateFileActivityMonitor
	am := CreateFileActivityMonitor(&client)

	// Start
	am.Start()

	nonExistentFile := "non-existent-file"

	// Open a non-existent file
	_, _ = os.Open(nonExistentFile)

	// Stop
	am.Stop()

	// Check that the file was recorded, loop through the list of files and check if "non-existent-file" is in the list
	found := false
	for _, file := range client.listOfFiles {
		fmt.Println(file)
		if file == nonExistentFile {
			fmt.Println("Found")
			found = true
			break
		}
	}

	if !found {
		t.Error("File not found")
	}

	fmt.Println("Done")

}
