//go:build windows

package launcher

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// mediumRID is SECURITY_MANDATORY_MEDIUM_RID.
const mediumRID = 0x2000

// TestLeastPrivilegeTokenIsMediumWithOnlyChangeNotify restricts this test process's own token —
// the same transform applied to the LocalService token in production — and reads the result back.
func TestLeastPrivilegeTokenIsMediumWithOnlyChangeNotify(t *testing.T) {
	var own windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &own)
	if err != nil {
		t.Fatalf("OpenProcessToken: %v", err)
	}
	defer own.Close()

	tok, err := leastPrivilegeToken(own)
	if err != nil {
		t.Fatalf("leastPrivilegeToken: %v", err)
	}
	defer tok.Close()

	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		t.Fatalf("TokenIntegrityLevel: %v", err)
	}
	sid := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])).Label.Sid
	if rid := sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)); rid != mediumRID {
		t.Errorf("integrity RID = 0x%x, want medium (0x%x)", rid, mediumRID)
	}

	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	buf = make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n); err != nil {
		t.Fatalf("TokenPrivileges: %v", err)
	}
	var changeNotify windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &changeNotify); err != nil {
		t.Fatalf("LookupPrivilegeValue: %v", err)
	}
	for _, p := range (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0])).AllPrivileges() {
		if p.Luid != changeNotify {
			t.Errorf("privilege LUID %v survived DISABLE_MAX_PRIVILEGE", p.Luid)
		}
	}
}
