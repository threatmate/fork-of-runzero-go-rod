//go:build !windows

package launcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

type osAttributes struct {
	UID int
	GID int
}

func (l *Launcher) osResolveAttributes() {
	l.osAttributes = &osAttributes{}
	l.osAttributes.UID = l.Browser.UID
	l.osAttributes.GID = l.Browser.GID
}

func (l *Launcher) osSetupCmd(ctx context.Context, cmd *exec.Cmd) error {
	var err error

	// Do NOT pre-emptively add --no-sandbox here.
	//
	// This used to read /proc/sys/kernel/apparmor_restrict_unprivileged_userns and append the flag
	// whenever it was 1, which is the default on Ubuntu 23.10 and later. That sysctl says user
	// namespaces are restricted SYSTEM-WIDE; it does not say they are unavailable to this
	// particular binary, which is precisely what an AppArmor profile changes. Chromium's own
	// guidance is to grant userns to the browser with such a profile
	// (https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md),
	// and this check defeated exactly that: measured on Ubuntu 24.04, the binary sandboxes
	// correctly when run directly under a profile granting `userns`, and got --no-sandbox anyway
	// when launched through here.
	//
	// What replaces it is a RETRY, and the retry is NOT in this package: it is in
	// cmd/webshot/chrome, whose Init re-launches with --no-sandbox once a launch has actually
	// failed with ErrNoSandbox. So a host where the sandbox genuinely cannot work still ends up
	// with the flag -- one failed launch later, and only when it is really needed -- while a host
	// where it CAN work keeps its sandbox, which for a browser rendering untrusted pages is the
	// whole point.
	//
	// The consequence, and the reason this is spelled out: a caller that drives lib/launcher
	// DIRECTLY gets no retry at all. Where the sandbox really is unavailable to the browser being
	// launched, that launch returns ErrNoSandbox and that is the end of it.
	//
	// "Really unavailable" is NOT the same as "the sysctl is 1", which is the very over-reading
	// the paragraph above exists to correct. What decides it is whether an AppArmor profile grants
	// userns to THIS binary, and profiles are per-path: measured on a host with
	// apparmor_restrict_unprivileged_userns=1 that also ships an /etc/apparmor.d/chrome profile,
	// lib/launcher's own TestLaunchUserMode still panics with "No usable sandbox!" against this
	// tree -- because that profile covers the distro's Chrome, not the Chrome-for-Testing binary
	// the launcher had fetched. A caller whose browser IS covered launches sandboxed and sees
	// none of this.
	//
	// Two things follow. Do not remove the retry in cmd/webshot/chrome believing this package
	// covers it -- it does not. And do not offer this change upstream as-is; it would break
	// go-rod's own users. Making it safe for them means moving the ErrNoSandbox retry down into
	// Launch(), at which point the pre-emptive flag can go for everyone.

	if l.Browser.GetXVFB() {
		*cmd = *exec.CommandContext(ctx, "xvfb-run", cmd.Args...) //nolint:gosec
	}
	cmd.SysProcAttr, err = l.getSysProcAttr(l.Browser.UID, l.Browser.GID)
	return err
}

// getSysProcAttr returns the SysProcAttr for non-Windows platforms.
func (l *Launcher) getSysProcAttr(uid, gid int) (*syscall.SysProcAttr, error) {
	v := &syscall.SysProcAttr{
		Setpgid: true,
	}
	// Request SIGKILL-on-parent-death on Linux so orphaned Chrome trees
	// cannot survive a crashed/killed launcher.
	setPdeathsig(v)
	if os.Geteuid() == 0 && uid != 0 {
		// A uid without a gid would leave the browser in group 0, able to write anything
		// group-root-writable: the same hazard as the supplementary groups below.
		if gid == 0 {
			return nil, fmt.Errorf("refusing to run the browser as uid %d in group 0: set WithGID too", uid)
		}
		// Groups set to an empty list, not NoSetGroups: with NoSetGroups the child keeps the
		// caller's supplementary groups, and a root caller usually carries group 0, which would
		// leave the unprivileged browser able to write anything group-root-writable.
		cred := &syscall.Credential{
			Uid:    uint32(uid),
			Gid:    uint32(gid),
			Groups: []uint32{},
		}
		v.Credential = cred
	}
	return v, nil
}

const rlimitNoFiles = 1048576

func (l *Launcher) ensureUserPermissions(userDir, binPath string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if l.Browser.UID == 0 {
		return nil
	}
	var res error

	if err := l.osEnsureUserPermissionsUserDir(userDir); err != nil {
		res = errors.Join(res, fmt.Errorf("user dir permissions: %w", err))
	}
	if err := l.osEnsureUserPermissionsBinary(binPath); err != nil {
		res = errors.Join(res, fmt.Errorf("binary permissions: %w", err))
	}
	return res
}

// osEnsureUserPermissionsBinary ensures that the binary and its leading paths
// have execute permissions for user, group, and other.
func (l *Launcher) osEnsureUserPermissionsBinary(binPath string) error {
	if binPath == "" {
		return fmt.Errorf("no binary path")
	}
	st, err := os.Stat(binPath)
	if err != nil {
		return fmt.Errorf("bin path %s: %w", binPath, err)
	}
	if st.IsDir() {
		return fmt.Errorf("bin path %s is a directory", binPath)
	}

	err = filepath.Walk(binPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the chmod only when it would change nothing, i.e. the binary is already exactly
		// 0755 with no setuid, setgid or sticky bit. A chmod is not free even then: on an overlay
		// filesystem it copies the whole file up into the writable layer first, and under gVisor
		// (Cloud Run) that layer is memory. For chrome-headless-shell that was a 202 MiB copy,
		// paid on the first launch as a dropped user in every container.
		//
		// Exactly 0755, not "readable and executable by everyone": the chmod also takes away
		// group and other write and the setuid bits, and those must still go. (It does not change
		// the owner, so a binary owned by the dropped user stays writable by it either way.)
		//
		// Stat rather than info: Walk Lstats its root, so for a symlinked binary info describes
		// the link, whose mode is always 0777, and Chmod follows it to the target.
		target, statErr := os.Stat(path)
		if statErr == nil && target.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0o755 {
			return nil
		}
		_ = os.Chmod(path, 0o755) //nolint:gosec
		return nil
	})
	if err != nil {
		return fmt.Errorf("bin path %s: %w", binPath, err)
	}

	// Try to ensure all leading paths are read/execute
	if err := l.osEnsureLeadingPathReadExec(binPath); err != nil {
		return fmt.Errorf("leading path read/exec %s: %w", binPath, err)
	}

	return nil
}

// osEnsureLeadingPathReadExec ensures that all components of the
// path allow read and execute permissions for user, group, and other.
func (l *Launcher) osEnsureLeadingPathReadExec(src string) error {
	// Ensure that all leading paths have execute enabled for user, group, and other
	base, err := filepath.Abs(src)
	if err != nil {
		return fmt.Errorf("resolve base path %s: %w", src, err)
	}
	pname := "/"
	for part := range strings.SplitSeq(base, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		pname = filepath.Join(pname, part)
		st, err := os.Stat(pname)
		if err != nil {
			return fmt.Errorf("stat path %s: %w", pname, err)
		}
		// We've reached the file at the end of the path
		if !st.IsDir() {
			return nil
		}
		cperm := st.Mode().Perm()
		// Already traversable by everyone: leave it alone, for the same reason as the binary. The
		// chmod below would only add bits, so skipping it removes nothing -- except that it would
		// also clear a sticky or setgid bit, since cperm holds only the permission bits, and on
		// /tmp, where the default profile lives, that is a bit worth keeping.
		if cperm&0o111 == 0o111 {
			continue
		}
		if err := os.Chmod(pname, cperm|0o111); err != nil { //nolint:gosec
			l.logger.Errorf("failed to chmod path %s as %o: %s", pname, cperm|0o111, err)
		}
	}
	return nil
}

func (l *Launcher) osEnsureUserPermissionsUserDir(userDir string) error {
	// Validate user dir
	if userDir == "" {
		return fmt.Errorf("no user-data-dir")
	}
	st, err := os.Stat(userDir)
	if err != nil {
		return fmt.Errorf("userdir %s: %w", userDir, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("userdir %s is not a directory", userDir)
	}

	err = filepath.Walk(userDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == userDir {
			// Ensure that the user directory is owned by the user
			if err := os.Chown(path, l.Browser.UID, l.Browser.GID); err != nil {
				return fmt.Errorf("chown path %s: %w", path, err)
			}
			return nil
		}
		// Try to ensure all leading paths are 755
		_ = os.Chmod(path, 0o755) //nolint:gosec
		return nil
	})
	if err != nil {
		return fmt.Errorf("userdir path %s: %w", userDir, err)
	}

	// Try to ensure all leading paths are read/execute
	if err := l.osEnsureLeadingPathReadExec(userDir); err != nil {
		return fmt.Errorf("leading path read/exec %s: %w", userDir, err)
	}

	return nil
}

// osEnsureApplicationPermissions enables read/execute permissions for everyone.
func (b *Browser) osEnsureApplicationPermissions(dir string) error {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		_ = os.Chmod(path, 0o755) //nolint:gosec
		return nil
	})
	return nil
}

func killGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
