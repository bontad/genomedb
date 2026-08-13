//go:build linux

package client

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// detectDebugger reads /proc/self/status' TracerPid field — the kernel's
// own record of which process (if any) is ptrace-attached to this one.
// Non-zero means traced: a debugger, strace, or a memory-inspection tool.
func detectDebugger() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false
		}
		pid, err := strconv.Atoi(fields[1])
		return err == nil && pid != 0
	}
	return false
}
