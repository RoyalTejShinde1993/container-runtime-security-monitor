package container

import (
	"fmt"
	"os"
	"strings"
)

func ResolveContainer(pid uint32) string {

	path := fmt.Sprintf("/proc/%d/cgroup", pid)

	data, err := os.ReadFile(path)
	if err != nil {
		return "host"
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {

		if strings.Contains(line, "docker") ||
			strings.Contains(line, "containerd") {

			parts := strings.Split(line, "/")

			return parts[len(parts)-1]
		}
	}

	return "host"
}
