//go:build !darwin && !linux && !windows

package client

// detectDebugger has no platform-specific implementation on this OS in
// this demo; it degrades to "no signal" rather than failing the build.
// Add a real check (e.g. reading the platform's process-trace flag) to
// bring this GOOS up to parity with watchdog_darwin.go / watchdog_linux.go.
func detectDebugger() bool { return false }

func detectRemoteSession() bool { return false }
