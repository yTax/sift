//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// freeDisk returns the bytes free on dir's drive, or -1 when it can't tell.
func freeDisk(dir string) int64 {
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return -1
	}
	var free uint64
	if r, _, _ := getDiskFreeSpaceEx.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&free)), 0, 0); r == 0 {
		return -1
	}
	return int64(free)
}
