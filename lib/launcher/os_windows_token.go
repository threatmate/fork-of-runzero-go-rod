//go:build windows

package launcher

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The service-logon token LogonUser hands back for LocalService or NetworkService is not a small
// token. Measured on Windows 11 under a SYSTEM agent: the browser process ran at System integrity
// (0x4000) with SeImpersonatePrivilege and SeCreateGlobalPrivilege enabled. SeImpersonatePrivilege
// is the well-known step from a service account back to SYSTEM, so a browser rendering untrusted
// pages on that token is one bug away from SYSTEM whatever account name it carries.
//
// leastPrivilegeToken returns what a desktop Chrome would have instead: every privilege but
// SeChangeNotifyPrivilege removed (DISABLE_MAX_PRIVILEGE), at Medium integrity. Chromium's own
// sandbox then derives its Low/Untrusted, restricted renderer tokens from that, exactly as it does
// for a signed-in user. The caller owns the returned token; the input is left open.

const disableMaxPrivilege = 0x1

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

func leastPrivilegeToken(token windows.Token) (windows.Token, error) {
	var restricted windows.Token
	r, _, err := procCreateRestrictedToken.Call(
		uintptr(token), disableMaxPrivilege,
		0, 0, // SIDs to disable
		0, 0, // privileges to delete (DISABLE_MAX_PRIVILEGE covers them)
		0, 0, // restricting SIDs
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", err)
	}

	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		_ = restricted.Close()
		return 0, fmt.Errorf("medium integrity SID: %w", err)
	}
	label := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY},
	}
	err = windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(medium))
	if err != nil {
		_ = restricted.Close()
		return 0, fmt.Errorf("set medium integrity: %w", err)
	}
	return restricted, nil
}
