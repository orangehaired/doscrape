//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

func osAbsoluteCap() (uint64, error) {
	data, err := os.ReadFile("/proc/sys/fs/nr_open")
	if err != nil {
		return 1 << 20, err
	}
	s := strings.TrimSpace(string(data))
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 1 << 20, err
	}
	return v, nil
}
