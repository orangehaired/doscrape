package main

import (
	"fmt"
	"log"
	"runtime"

	"golang.org/x/sys/unix"
)

// SetRlimitMax Reference: from github
func SetRlimitMax(target uint64) (soft, hard uint64, err error) {
	const res = unix.RLIMIT_NOFILE

	var r unix.Rlimit
	if err = unix.Getrlimit(res, &r); err != nil {
		return 0, 0, fmt.Errorf("getrlimit: %w", err)
	}
	origSoft, origHard := r.Cur, r.Max

	osCap, _ := osAbsoluteCap()

	if target == 0 || target > osCap {
		target = osCap
	}

	if r.Max < target {
		r.Max = target
		if e := unix.Setrlimit(res, &r); e != nil {
			r.Max = origHard
		}
	}

	r.Cur = target
	if r.Cur > r.Max {
		r.Cur = r.Max
	}
	if e := unix.Setrlimit(res, &r); e != nil {
		r.Cur = r.Max
		unix.Setrlimit(res, &r)
	}

	unix.Getrlimit(res, &r)

	log.Printf("[rlimit] %s NOFILE: orig soft=%d hard=%d, final soft=%d hard=%d",
		runtime.GOOS, origSoft, origHard, r.Cur, r.Max)

	return uint64(r.Cur), uint64(r.Max), nil
}
