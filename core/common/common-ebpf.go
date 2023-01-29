package common

import (
	"fmt"
	"log"

	"github.com/cilium/ebpf/rlimit"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

var containerCollection containercollection.ContainerCollection

func init() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithRuncFanotify(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: runtimeclient.DockerName},
				{Name: runtimeclient.ContainerdName},
				{Name: runtimeclient.CrioName},
			}),
	}

	// Initialize the container collection
	err := containerCollection.Initialize(opts...)
	if err != nil {
		log.Fatalf("Failed to initialize container collection: %v", err)
	}
}

// Global variable to store module names
var ModuleNames []string

func RegisterPart(name string) {
	ModuleNames = append(ModuleNames, name)
}

func GetContainerIdForNsMntId(nsMntId uint64) (string, error) {
	container := containerCollection.LookupContainerByMntns(nsMntId)
	if container == nil {
		return "", fmt.Errorf("container not found for nsMntId %d", nsMntId)
	}
	return container.ID, nil
}
