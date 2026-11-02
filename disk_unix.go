//go:build !windows

package main

import "syscall"

// freeDisk returns the bytes free on dir's drive, or -1 when it can't tell.
func freeDisk(dir string) int64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return -1
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
