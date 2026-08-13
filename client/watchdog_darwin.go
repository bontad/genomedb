//go:build darwin

package client

import (
	"os"

	"golang.org/x/sys/unix"
)

// P_TRACED is the BSD/xnu kernel process-flag bit (sys/proc.h) set on a
// process currently being ptrace-attached — the same flag a debugger or a
// memory-dumping tool attaching via ptrace(2)/task_for_pid leaves behind.
const pTraced = 0x00000800

// detectDebugger asks the kernel directly (via sysctl KERN_PROC_PID, the
// same call `ps` uses) whether this process is currently traced. This is
// a real, working check on macOS — not a stub — though a sufficiently
// privileged attacker could in principle patch it out from kernel space;
// it is one signal among several fused by the watchdog, not a sole line
// of defense.
func detectDebugger() bool {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return false
	}
	return kp.Proc.P_flag&pTraced != 0
}
