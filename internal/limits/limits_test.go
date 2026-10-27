package limits

import (
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func cgroup(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestMemoryLimit(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  int64
		ok    bool
	}{
		{"cgroup v2 limit", map[string]string{"memory.max": "134217728\n"}, 134217728, true},
		{"cgroup v2 unlimited", map[string]string{"memory.max": "max\n"}, 0, false},
		{"cgroup v1 limit", map[string]string{"memory/memory.limit_in_bytes": "268435456\n"}, 268435456, true},
		{"cgroup v1 unlimited", map[string]string{"memory/memory.limit_in_bytes": "9223372036854771712\n"}, 0, false},
		{"no cgroup files", map[string]string{}, 0, false},
		{"garbage", map[string]string{"memory.max": "lots"}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := MemoryLimit(cgroup(t, tc.files))
			if got != tc.want || ok != tc.ok {
				t.Fatalf("got %d %v, want %d %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestApplyMemoryLimit(t *testing.T) {
	previous := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })

	t.Setenv("GOMEMLIMIT", "")
	res, err := ApplyMemoryLimit(cgroup(t, map[string]string{"memory.max": "100000000"}))
	if err != nil || res.Source != "cgroup" || res.Limit != 90000000 || debug.SetMemoryLimit(-1) != 90000000 {
		t.Fatalf("cgroup: %+v %v", res, err)
	}

	debug.SetMemoryLimit(math.MaxInt64)
	res, _ = ApplyMemoryLimit(cgroup(t, map[string]string{"memory.max": "max"}))
	if res.Source != "none" || debug.SetMemoryLimit(-1) != math.MaxInt64 {
		t.Fatalf("unlimited: %+v", res)
	}

	t.Setenv("GOMEMLIMIT", "50MiB")
	debug.SetMemoryLimit(50 << 20)
	res, _ = ApplyMemoryLimit(cgroup(t, map[string]string{"memory.max": "100000000"}))
	if res.Source != "GOMEMLIMIT" || debug.SetMemoryLimit(-1) != 50<<20 {
		t.Fatalf("an explicit GOMEMLIMIT was overridden: %+v", res)
	}
}
