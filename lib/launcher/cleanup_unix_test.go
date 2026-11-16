//go:build !windows

package launcher_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/runZeroInc/go-rod/lib/launcher"
)

// TestCleanupKillsTheGroupWithoutWaitingOutItsChildren: a browser with a child holding its stderr,
// as Chromium's are, is gone -- itself and its group -- well inside the 1 s cmd.WaitDelay that
// Cleanup used to sit out before its 1 s Kill sleep.
func TestCleanupKillsTheGroupWithoutWaitingOutItsChildren(t *testing.T) {
	devtools := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"webSocketDebuggerUrl": "ws://%s/devtools/browser/fake"}`, r.Host)
	}))
	defer devtools.Close()
	host := strings.TrimPrefix(devtools.URL, "http://")
	script := filepath.Join(t.TempDir(), "browser")
	body := fmt.Sprintf("#!/bin/sh\necho \"DevTools listening on ws://%s/devtools/browser/fake\" >&2\nsleep 300 &\nsleep 300\n", host)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 3; round++ {
		l := launcher.NewMust(launcher.WithContext(context.Background())).Bin(script)
		if _, err := l.Launch(); err != nil {
			t.Fatalf("launch: %v", err)
		}
		pid := l.PID()
		start := time.Now()
		l.Cleanup()
		took := time.Since(start)
		if took >= 900*time.Millisecond {
			t.Errorf("round %d: Cleanup took %s", round, took)
		}
		time.Sleep(100 * time.Millisecond)
		if syscall.Kill(-pid, 0) == nil {
			t.Errorf("round %d: the browser's process group outlived Cleanup", round)
		}
	}
}
