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

// permissionsTestDir is a temporary directory for osEnsureUserPermissionsBinary, which walks the
// path from / and makes every directory on it traversable. Run against a temp dir under a private
// home directory (TMPDIR=~/.cache/...), that would widen the home directory itself, so the test
// is skipped there rather than allowed to.
func permissionsTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// t.TempDir makes a private parent of its own, per test, and the umask decides both modes;
	// those two belong to the test, so give them a known starting point. Everything above them
	// does not.
	for _, own := range []string{filepath.Dir(dir), dir} {
		if err := os.Chmod(own, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for parent := filepath.Dir(filepath.Dir(dir)); ; parent = filepath.Dir(parent) {
		st, err := os.Stat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o111 != 0o111 {
			t.Skipf("%s is not traversable by everyone, and this test would change that; set TMPDIR to a directory under /tmp", parent)
		}
		if parent == "/" {
			break
		}
	}
	return dir
}

func writeBinary(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// A chmod that changes nothing still writes the inode, which is what makes an overlay copy the
// file up. The inode's change time is the observable trace of that write.
func TestEnsureUserPermissionsBinaryLeavesAnExecutableBinaryAlone(t *testing.T) {
	dir := permissionsTestDir(t)
	bin := filepath.Join(dir, "browser")
	writeBinary(t, bin, 0o755)
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

// Everything that is not already exactly 0755 is still set to 0755: a binary others cannot run,
// one they could rewrite, and one with a setuid bit. Through a symlink too, which is how the
// production image names its browser.
func TestEnsureUserPermissionsBinaryStillSetsEverythingElseTo0755(t *testing.T) {
	dir := permissionsTestDir(t)
	inner := filepath.Join(dir, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	l := &Launcher{logger: logrus.NewEntry(logrus.New())}

	for name, mode := range map[string]os.FileMode{
		"owner only":      0o700,
		"not executable":  0o644,
		"world writable":  0o777,
		"group writable":  0o775,
		"setuid":          0o755 | os.ModeSetuid,
		"setgid":          0o755 | os.ModeSetgid,
		"behind symlink":  0o700,
		"in a closed dir": 0o700,
	} {
		t.Run(name, func(t *testing.T) {
			parent := dir
			if name == "in a closed dir" {
				parent = inner
			}
			bin := filepath.Join(parent, filepath.Base(t.Name()))
			writeBinary(t, bin, mode)
			path := bin
			if name == "behind symlink" {
				path = bin + ".link"
				if err := os.Symlink(bin, path); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.osEnsureUserPermissionsBinary(path); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(bin)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode() != 0o755 {
				t.Errorf("mode is %v, want -rwxr-xr-x", st.Mode())
			}
		})
	}
	st, err := os.Stat(inner)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o711 {
		t.Errorf("leading directory mode is %o, want 711", st.Mode().Perm())
	}
}
