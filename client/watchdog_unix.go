//go:build darwin || linux

package client

import "os"

// detectRemoteSession checks for the environment markers a shell gets
// when it (or an ancestor) was started over SSH — the closest portable
// analogue to "is this an RDP session" on Unix. A real deployment would
// also check the controlling tty and utmp/wtmp session records; this is
// enough to demonstrate a genuine, working signal rather than a stub.
func detectRemoteSession() bool {
	return os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != ""
}
