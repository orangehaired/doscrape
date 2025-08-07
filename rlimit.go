package main

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// SetRlimitMax tries to raise RLIMIT_NOFILE (open file descriptors) as high as allowed.
// It returns the final (soft, hard) limits actually set.
// Referenced: Some github repo.
func SetRlimitMax(target uint64) (soft, hard uint64, err error) {
	const res = unix.RLIMIT_NOFILE

	var r unix.Rlimit
	if err = unix.Getrlimit(res, &r); err != nil {
		return 0, 0, fmt.Errorf("Getrlimit: %w", err)
	}
	origSoft, origHard := r.Cur, r.Max

	osCap, capWarn := osAbsoluteCap()

	want := target
	if want == 0 || want > osCap {
		want = osCap
	}

	if r.Max < want {
		r.Max = want
		if e := unix.Setrlimit(res, &r); e != nil {
			capWarn = errors.Join(capWarn, fmt.Errorf("cannot raise hard limit to %d: %w", want, e))
			r.Max = origHard
		}
	}

	r.Cur = want
	if r.Cur > r.Max {
		r.Cur = r.Max
	}
	if e := unix.Setrlimit(res, &r); e != nil {
		r.Cur = r.Max
		if e2 := unix.Setrlimit(res, &r); e2 != nil {
			return uint64(origSoft), uint64(origHard), fmt.Errorf("Setrlimit failed (soft=%d, hard=%d): %v / fallback: %v", r.Cur, r.Max, e, e2)
		}
	}

	if e := unix.Getrlimit(res, &r); e != nil {
		return uint64(r.Cur), uint64(r.Max), fmt.Errorf("Getrlimit (final): %w", e)
	}

	log.Printf("[rlimit] NOFILE: orig soft=%d hard=%d, requested=%d, final soft=%d hard=%d",
		origSoft, origHard, want, r.Cur, r.Max)
	if capWarn != nil {
		log.Printf("[rlimit] NOTE: %v", capWarn)
	}
	if r.Cur < want {
		log.Printf("[rlimit] Soft limit (%d) is below requested (%d). You may need root/administrator privileges or system-level config.", r.Cur, want)
	}

	return uint64(r.Cur), uint64(r.Max), nil
}

// osAbsoluteCap returns the maximum per-process NOFILE the OS will allow without sysctl/launchctl changes.
// On Linux this is /proc/sys/fs/nr_open; on macOS it's min(kern.maxfilesperproc, kern.maxfiles).
func osAbsoluteCap() (cap uint64, warn error) {
	switch runtime.GOOS {
	case "linux":
		b, err := os.ReadFile("/proc/sys/fs/nr_open")
		if err != nil {
			return 1 << 20, fmt.Errorf("cannot read /proc/sys/fs/nr_open: %w (fallback 1<<20)", err) // ~1,048,576
		}
		n, err := parseUint(strings.TrimSpace(string(b)))
		if err != nil {
			return 1 << 20, fmt.Errorf("parse nr_open: %w (fallback 1<<20)", err)
		}
		return n, nil

	case "darwin":
		perProc, err1 := sysctlUint64("kern.maxfilesperproc")
		total, err2 := sysctlUint64("kern.maxfiles")
		var buf bytes.Buffer
		if err1 != nil {
			fmt.Fprintf(&buf, "kern.maxfilesperproc: %v. ", err1)
		}
		if err2 != nil {
			fmt.Fprintf(&buf, "kern.maxfiles: %v. ", err2)
		}
		if err1 != nil || err2 != nil {
			// Fallback commonly seen ceiling
			return 10240, fmt.Errorf(strings.TrimSpace(buf.String()))
		}
		if perProc > total {
			perProc = total
		}
		return perProc, nil

	default:
		// Other Unix-y OS: be conservative
		return 65535, fmt.Errorf("unsupported GOOS=%s, using conservative cap", runtime.GOOS)
	}
}

func sysctlUint64(name string) (uint64, error) {
	// x/sys/unix has SysctlUint32; values on macOS for these keys fit 32-bit.
	u32, err := unix.SysctlUint32(name)
	if err != nil {
		return 0, err
	}
	return uint64(u32), nil
}

func parseUint(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}
