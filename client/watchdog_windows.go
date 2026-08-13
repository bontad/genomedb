//go:build windows

package client

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modwtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")

	procIsDebuggerPresent           = modkernel32.NewProc("IsDebuggerPresent")
	procGetCurrentProcessId         = modkernel32.NewProc("GetCurrentProcessId")
	procProcessIdToSessionId        = modkernel32.NewProc("ProcessIdToSessionId")
	procWTSQuerySessionInformationW = modwtsapi32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = modwtsapi32.NewProc("WTSFreeMemory")
)

const (
	wtsCurrentServerHandle = 0
	wtsClientProtocolType  = 16 // WTS_INFO_CLASS.WTSClientProtocolType
	wtsProtocolTypeRDP     = 2  // WTSQuerySessionInformation return value for an RDP session
)

// detectDebugger calls the Win32 IsDebuggerPresent API — the same signal
// most anti-tamper agents check first. It only sees debuggers attached
// through the standard Windows debug APIs, not kernel-level or hardware
// ones, which is exactly why the watchdog treats it as one weighted
// signal among several rather than a sole trigger.
func detectDebugger() bool {
	ret, _, _ := procIsDebuggerPresent.Call()
	return ret != 0
}

// detectRemoteSession asks Terminal Services which protocol drives this
// process's session. An RDP client reports protocol type 2; the local
// console reports 0.
func detectRemoteSession() bool {
	pid, _, _ := procGetCurrentProcessId.Call()

	var sessionID uint32
	ok, _, _ := procProcessIdToSessionId.Call(pid, uintptr(unsafe.Pointer(&sessionID)))
	if ok == 0 {
		return false
	}

	var buf uintptr
	var bytesReturned uint32
	ok, _, _ = procWTSQuerySessionInformationW.Call(
		uintptr(wtsCurrentServerHandle),
		uintptr(sessionID),
		uintptr(wtsClientProtocolType),
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&bytesReturned)),
	)
	if ok == 0 || buf == 0 {
		return false
	}
	defer procWTSFreeMemory.Call(buf)

	protocolType := *(*uint16)(unsafe.Pointer(buf))
	return protocolType == wtsProtocolTypeRDP
}
