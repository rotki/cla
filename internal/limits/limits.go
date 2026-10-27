// Package limits makes the Go runtime respect the container's memory limit.
//
// Go sizes GOMAXPROCS from the container's CPU limit by itself (since Go
// 1.25), but it does not read the memory limit: without GOMEMLIMIT the
// garbage collector lets the heap grow until the kernel kills the container.
// ApplyMemoryLimit reads the cgroup limit and sets a soft limit below it, so
// the collector works harder as memory fills instead of the process dying.
package limits

import (
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// Share is the part of the container limit given to the Go heap. The rest
// covers goroutine stacks, runtime overhead and memory the runtime has not
// returned to the system yet.
const Share = 0.9

// unlimited is what cgroup v1 reports when no limit is set: a huge number
// rounded to the page size. Anything above 1 PiB counts as none.
const unlimited = 1 << 50

// MemoryLimit returns the container's memory limit in bytes, read from the
// cgroup filesystem under root ("/sys/fs/cgroup" in a container), and false
// when there is none.
func MemoryLimit(root string) (int64, bool) {
	// cgroup v2: a single memory.max, "max" when unlimited.
	if data, err := os.ReadFile(filepath.Join(root, "memory.max")); err == nil {
		return parse(string(data))
	}
	// cgroup v1.
	if data, err := os.ReadFile(filepath.Join(root, "memory", "memory.limit_in_bytes")); err == nil {
		return parse(string(data))
	}
	return 0, false
}

func parse(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n >= unlimited {
		return 0, false
	}
	return n, true
}

// Result says what ApplyMemoryLimit did.
type Result struct {
	// Source is "GOMEMLIMIT", "cgroup" or "none".
	Source string
	// Container is the container limit, when read from the cgroup.
	Container int64
	// Limit is the soft limit now in force, 0 when none.
	Limit int64
}

// ApplyMemoryLimit sets the runtime's soft memory limit to Share of the
// container limit. An explicit GOMEMLIMIT always wins and is left alone.
func ApplyMemoryLimit(root string) (Result, error) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return Result{Source: "GOMEMLIMIT", Limit: debug.SetMemoryLimit(-1)}, nil
	}
	container, ok := MemoryLimit(root)
	if !ok {
		return Result{Source: "none"}, nil
	}
	limit := int64(float64(container) * Share)
	if limit <= 0 {
		return Result{}, errors.New("container memory limit too small")
	}
	debug.SetMemoryLimit(limit)
	return Result{Source: "cgroup", Container: container, Limit: limit}, nil
}
