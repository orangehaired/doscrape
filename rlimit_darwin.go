//go:build darwin

package main

import (
	"golang.org/x/sys/unix"
)

func osAbsoluteCap() (uint64, error) {
	perProc, err1 := sysctlUint64("kern.maxfilesperproc")
	total, err2 := sysctlUint64("kern.maxfiles")
	if err1 != nil || err2 != nil {
		return 10240, nil
	}
	if perProc > total {
		perProc = total
	}
	return perProc, nil
}

func sysctlUint64(name string) (uint64, error) {
	u32, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, err
	}
	return uint64(u32), nil
}
