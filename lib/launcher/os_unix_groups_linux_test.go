//go:build linux

package launcher

import (
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/sirupsen/logrus"
)

// TestDroppedUserKeepsNoSupplementaryGroups runs a child the way Launch runs the browser, as a
// root caller dropping to an unprivileged uid, and reads the child's groups back. Root usually
// carries supplementary group 0, and a child that kept it could write anything group-root-writable.
// Runs only as root.
func TestDroppedUserKeepsNoSupplementaryGroups(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to drop privileges at all")
	}
	l := &Launcher{logger: logrus.NewEntry(logrus.New())}
	attr, err := l.getSysProcAttr(65534, 65534)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/cat", "/proc/self/status")
	cmd.SysProcAttr = attr
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	status := string(out)
	if m := regexp.MustCompile(`(?m)^Uid:\s+(\d+)`).FindStringSubmatch(status); m == nil || m[1] != "65534" {
		t.Fatalf("child uid: %v", m)
	}
	groups := regexp.MustCompile(`(?m)^Groups:(.*)$`).FindStringSubmatch(status)
	if groups == nil {
		t.Fatal("no Groups line")
	}
	if g := regexp.MustCompile(`\S+`).FindAllString(groups[1], -1); len(g) != 0 {
		t.Errorf("the dropped child kept supplementary groups %v", g)
	}
}

// TestDroppingToAUserWithoutAGroupIsRefused: Browser.GID defaults to 0, so a caller that sets only
// a uid would get a browser in group 0. Runs only as root, where the drop happens.
func TestDroppingToAUserWithoutAGroupIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root, to drop privileges at all")
	}
	l := &Launcher{logger: logrus.NewEntry(logrus.New())}
	if _, err := l.getSysProcAttr(65534, 0); err == nil {
		t.Error("a drop to uid 65534 in group 0 was allowed")
	}
	if _, err := l.getSysProcAttr(0, 0); err != nil {
		t.Errorf("staying root is not a drop: %v", err)
	}
}
