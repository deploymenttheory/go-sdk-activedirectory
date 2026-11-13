//go:build windows && (amd64 || arm64)

package main

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networkmanagement/netmanagement"
)

// stateNames and typeNames label the documented enum values. An unrecognised
// value is reported numerically rather than guessed at.
var stateNames = map[int32]string{
	1: "MsaInfoNotExist",
	2: "MsaInfoNotService",
	3: "MsaInfoCannotInstall",
	4: "MsaInfoCanInstall",
	5: "MsaInfoInstalled",
}

var typeNames = map[int32]string{
	0: "MsaAccountFalse",
	1: "StandAloneManagedServiceAccount",
	2: "GroupManagedServiceAccount",
	3: "DelegatedManagedServiceAccount",
}

func available(procs ...*win32.Proc) error {
	for _, proc := range procs {
		if err := proc.Find(); err != nil {
			return err
		}
	}
	return nil
}

func probe(account string) reading {
	result := reading{Account: account}

	// NetIsServiceAccount: the simple boolean. Recorded first so a host missing
	// the newer query export still produces something comparable.
	if err := available(netmanagement.Procs.NetIsServiceAccount); err != nil {
		result.Unsupported = append(result.Unsupported, fmt.Sprintf("NetIsServiceAccount: %v", err))
	} else {
		var isService foundation.BOOL
		status := uint32(netmanagement.NetIsServiceAccount(nil, account, &isService))
		result.IsStatus = &status
		if status == 0 {
			value := isService != 0
			result.IsServiceAccount = &value
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("NetIsServiceAccount: NTSTATUS 0x%08X", status))
		}
	}

	// NetQueryServiceAccount level 1 returns MSA_INFO_1 {State, AccountType},
	// which is the reading that distinguishes eligibility from installation.
	if err := available(netmanagement.Procs.NetQueryServiceAccount, netmanagement.Procs.NetApiBufferFree); err != nil {
		result.Unsupported = append(result.Unsupported, fmt.Sprintf("NetQueryServiceAccount: %v", err))
		return result
	}
	var buffer *byte
	status := uint32(netmanagement.NetQueryServiceAccount(nil, account, 1, &buffer))
	result.QueryStatus = &status
	// The buffer is owned by the API on success and must be released on every
	// path, including when the contents are rejected below.
	if buffer != nil {
		defer netmanagement.NetApiBufferFree(unsafe.Pointer(buffer))
	}
	if status != 0 {
		result.Errors = append(result.Errors, fmt.Sprintf("NetQueryServiceAccount: NTSTATUS 0x%08X", status))
		return result
	}
	if buffer == nil {
		result.Errors = append(result.Errors, "NetQueryServiceAccount returned no buffer with a success status")
		return result
	}
	info := (*netmanagement.MSA_INFO_1)(unsafe.Pointer(buffer))
	state := int32(info.State)
	accountType := int32(info.AccountType)
	result.State = &state
	result.AccountType = &accountType
	result.StateName = stateNames[state]
	result.AccountTypeName = typeNames[accountType]
	if result.StateName == "" {
		result.StateName = fmt.Sprintf("unknown(%d)", state)
	}
	if result.AccountTypeName == "" {
		result.AccountTypeName = fmt.Sprintf("unknown(%d)", accountType)
	}
	return result
}

// mutateNullPassword calls NetAddServiceAccount with a NULL password on an
// account that is already installed, and re-reads the state afterwards.
//
// This is the experiment behind issue #49. The lab showed
// Reset-ADServiceAccountPassword requires the account to be installed locally,
// which points at this call, but points at it is all the evidence does. The
// result records the status and the state either side so the two can be
// compared; it does not assert they are the same operation.
func mutateNullPassword(before reading, account string, flags uint32) reading {
	if err := available(netmanagement.Procs.NetAddServiceAccount); err != nil {
		before.Unsupported = append(before.Unsupported, fmt.Sprintf("NetAddServiceAccount: %v", err))
		return before
	}
	before.Mutated = true
	before.MutateFlags = &flags
	name := win32.UTF16Ptr(account)
	// A nil password pointer is the whole point: the host is asked to manage
	// the credential rather than being handed one.
	status := uint32(netmanagement.NetAddServiceAccountUTF16(nil, foundation.PWSTR(name), nil, flags))
	before.MutateStatus = &status
	runtime.KeepAlive(name)
	if status != 0 {
		before.Errors = append(before.Errors, fmt.Sprintf("NetAddServiceAccountUTF16(NULL password, flags=%d): NTSTATUS 0x%08X", flags, status))
	}
	// Re-read so the caller sees the state the mutation left behind.
	after := probe(account)
	before.State = after.State
	before.StateName = after.StateName
	before.AccountType = after.AccountType
	before.AccountTypeName = after.AccountTypeName
	before.IsServiceAccount = after.IsServiceAccount
	return before
}
