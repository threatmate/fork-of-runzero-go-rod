//go:build linux

package launcher

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func changeTime(t *testing.T, path string) syscall.Timespec {
	t.Helper()
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ctim
}

// A chmod that changes nothing still writes the inode, which is what makes an overlay copy the
// file up. The inode's change time is the observable trace of that write.
func TestEnsureUserPermissionsBinaryLeavesAnExecutableBinaryAlone(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "browser")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "chromium")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	l := &Launcher{logger: logrus.NewEntry(logrus.New())}

	for _, path := range []string{bin, link} {
		before, dirBefore := changeTime(t, bin), changeTime(t, dir)
		time.Sleep(20 * time.Millisecond) // past the filesystem's timestamp granularity
		if err := l.osEnsureUserPermissionsBinary(path); err != nil {
			t.Fatal(err)
		}
		if changeTime(t, bin) != before {
			t.Errorf("%s: the binary was chmodded although it was already 0755", path)
		}
		if changeTime(t, dir) != dirBefore {
			t.Errorf("%s: the binary's directory was chmodded although it was already traversable", path)
		}
	}
}

func TestEnsureUserPermissionsBinaryStillFixesOneOthersCannotRun(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "browser")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(dir, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(inner, "browser")
	if err := os.WriteFile(nested, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := &Launcher{logger: logrus.NewEntry(logrus.New())}
	for _, path := range []string{bin, nested} {
		if err := l.osEnsureUserPermissionsBinary(path); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode is %o, want 755", path, st.Mode().Perm())
		}
	}
	st, err := os.Stat(inner)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o711 {
		t.Errorf("leading directory mode is %o, want 711", st.Mode().Perm())
	}
}
