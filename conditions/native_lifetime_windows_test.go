//go:build windows && (amd64 || arm64)

package conditions

import (
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/memory"
)

type allocationLedger struct {
	live             map[foundation.HLOCAL]string
	allocated, freed int
}

func auditedNativeAPI(t *testing.T) (nativeAPI, *allocationLedger) {
	t.Helper()
	real := systemNativeAPI()
	api := real
	ledger := &allocationLedger{live: map[foundation.HLOCAL]string{}}
	acquired := func(handle foundation.HLOCAL, kind string) {
		t.Helper()
		if handle == 0 || ledger.live[handle] != "" {
			t.Fatalf("invalid or already-live allocation %x (%s)", handle, kind)
		}
		ledger.live[handle] = kind
		ledger.allocated++
	}
	api.convertSID = func(input string, sid *security.PSID) error {
		err := real.convertSID(input, sid)
		if err == nil {
			acquired(foundation.HLOCAL(*sid), "sid")
		}
		return err
	}
	api.allocate = func(flags memory.LOCAL_ALLOC_FLAGS, size uintptr) (foundation.HLOCAL, error) {
		handle, err := real.allocate(flags, size)
		if err == nil {
			acquired(handle, "descriptor")
		}
		return handle, err
	}
	api.parseDescriptor = func(input string, revision uint32, sd *security.PSECURITY_DESCRIPTOR, size *uint32) error {
		err := real.parseDescriptor(input, revision, sd, size)
		if err == nil {
			acquired(foundation.HLOCAL(*sd), "parsed-descriptor")
		}
		return err
	}
	api.formatDescriptor = func(sd security.PSECURITY_DESCRIPTOR, revision uint32, info security.OBJECT_SECURITY_INFORMATION, text *foundation.PWSTR, size *uint32) error {
		err := real.formatDescriptor(sd, revision, info, text, size)
		if err == nil {
			acquired(foundation.HLOCAL(uintptr(unsafe.Pointer(*text))), "sddl-text")
		}
		return err
	}
	api.free = func(handle foundation.HLOCAL) (foundation.HLOCAL, error) {
		if ledger.live[handle] == "" {
			t.Errorf("double free or unowned handle %x", handle)
			return handle, syscall.Errno(6)
		}
		remaining, err := real.free(handle)
		if err == nil {
			delete(ledger.live, handle)
			ledger.freed++
		}
		return remaining, err
	}
	t.Cleanup(func() {
		if len(ledger.live) != 0 {
			t.Errorf("native allocations left live: %v", ledger.live)
			for handle := range ledger.live {
				if _, err := real.free(handle); err != nil {
					t.Errorf("test cleanup: %v", err)
				}
			}
		}
	})
	return api, ledger
}

func lifetimeACE() ACE {
	return ACE{
		TrusteeSID: "S-1-1-0",
		AccessMask: 0x100,
		Condition:  Compare(Claim{User, "Department"}, Equal, Text("Finance")),
	}
}

func assertBalanced(t *testing.T, ledger *allocationLedger, allocations int) {
	t.Helper()
	if ledger.allocated != allocations || ledger.freed != allocations || len(ledger.live) != 0 {
		t.Fatalf(
			"allocation balance: allocated=%d freed=%d live=%v; expected %d",
			ledger.allocated,
			ledger.freed,
			ledger.live,
			allocations,
		)
	}
}

func TestNativeAllocationsBalancedOnSuccess(t *testing.T) {
	api, ledger := auditedNativeAPI(t)
	for n := 0; n < 100; n++ {
		compiled, err := api.compile(lifetimeACE())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := api.normalize(compiled); err != nil {
			t.Fatal(err)
		}
		// Compile owns a SID, descriptor and SDDL text; normalize owns a parsed
		// descriptor and SDDL text. These are real Windows allocations.
		assertBalanced(t, ledger, (n+1)*5)
	}
}

func TestNativeCompileReleasesResourcesAtEveryFailure(t *testing.T) {
	denied := syscall.Errno(5)
	cases := []struct {
		name        string
		allocations int
		inject      func(*nativeAPI)
	}{
		{"sid conversion", 0, func(api *nativeAPI) {
			api.convertSID = func(string, *security.PSID) error { return denied }
		}},
		{"acl initialization", 1, func(api *nativeAPI) {
			api.initializeACL = func(*security.ACL, uint32, security.ACE_REVISION) error { return denied }
		}},
		{"condition compilation", 1, func(api *nativeAPI) {
			api.addConditionalACE = func(*security.ACL, security.ACE_REVISION, security.ACE_FLAGS, byte, uint32, security.PSID, string, *uint32) error {
				return denied
			}
		}},
		{"descriptor allocation", 1, func(api *nativeAPI) {
			api.allocate = func(memory.LOCAL_ALLOC_FLAGS, uintptr) (foundation.HLOCAL, error) { return 0, denied }
		}},
		{"descriptor initialization", 2, func(api *nativeAPI) {
			api.initializeDescriptor = func(security.PSECURITY_DESCRIPTOR, uint32) error { return denied }
		}},
		{"dacl attachment", 2, func(api *nativeAPI) {
			api.setDACL = func(security.PSECURITY_DESCRIPTOR, bool, *security.ACL, bool) error { return denied }
		}},
		{"descriptor formatting", 2, func(api *nativeAPI) {
			api.formatDescriptor = func(security.PSECURITY_DESCRIPTOR, uint32, security.OBJECT_SECURITY_INFORMATION, *foundation.PWSTR, *uint32) error {
				return denied
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api, ledger := auditedNativeAPI(t)
			tc.inject(&api)
			if _, err := api.compile(lifetimeACE()); !errors.Is(err, denied) {
				t.Fatalf("native access-denied error lost: %v", err)
			}
			assertBalanced(t, ledger, tc.allocations)
		})
	}
}

func TestNativeNormalizeReleasesResourcesAtEveryFailure(t *testing.T) {
	denied := syscall.Errno(5)
	for _, stage := range []string{"parse", "format"} {
		t.Run(stage, func(t *testing.T) {
			api, ledger := auditedNativeAPI(t)
			allocations := 0
			if stage == "parse" {
				api.parseDescriptor = func(string, uint32, *security.PSECURITY_DESCRIPTOR, *uint32) error { return denied }
			} else {
				allocations = 1
				api.formatDescriptor = func(security.PSECURITY_DESCRIPTOR, uint32, security.OBJECT_SECURITY_INFORMATION, *foundation.PWSTR, *uint32) error {
					return denied
				}
			}
			if _, err := api.normalize("D:(A;;GA;;;WD)"); !errors.Is(err, denied) {
				t.Fatalf("native access-denied error lost: %v", err)
			}
			assertBalanced(t, ledger, allocations)
		})
	}
}

func TestNativeMissingExportFailsBeforeAllocation(t *testing.T) {
	api, ledger := auditedNativeAPI(t)
	missing := syscall.Errno(127)
	api.find = func(*win32.Proc) error { return missing }
	for _, run := range []func() (string, error){func() (string, error) { return api.compile(lifetimeACE()) }, func() (string, error) { return api.normalize("D:(A;;GA;;;WD)") }} {
		if _, err := run(); !errors.Is(err, ErrUnsupported) || !errors.Is(err, missing) {
			t.Fatalf("capability/native error not preserved: %v", err)
		}
	}
	assertBalanced(t, ledger, 0)
}

func TestNativeCleanupFailureRetainsBothErrors(t *testing.T) {
	for _, failOperation := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "successful operation", true: "failed operation"}[failOperation],
			func(t *testing.T) {
				api, ledger := auditedNativeAPI(t)
				operationError, cleanupError := syscall.Errno(5), syscall.Errno(6)
				if failOperation {
					api.setDACL = func(security.PSECURITY_DESCRIPTOR, bool, *security.ACL, bool) error { return operationError }
				}
				auditedFree := api.free
				failed := false
				api.free = func(handle foundation.HLOCAL) (foundation.HLOCAL, error) {
					if !failed {
						failed = true
						return handle, cleanupError
					}
					return auditedFree(handle)
				}
				_, err := api.compile(lifetimeACE())
				if !errors.Is(err, cleanupError) ||
					(failOperation && !errors.Is(err, operationError)) {
					t.Fatalf("operation/cleanup error lost: %v", err)
				}
				if len(ledger.live) != 1 || ledger.allocated-ledger.freed != 1 {
					t.Fatalf("remaining cleanup was skipped or retried: %+v", ledger)
				}
				// The injected LocalFree failure deliberately retains its allocation.
				// Release it in the test after proving the public error exposes failure.
				for handle := range ledger.live {
					if _, err := auditedFree(handle); err != nil {
						t.Fatal(err)
					}
				}
				assertBalanced(t, ledger, ledger.allocated)
			},
		)
	}
}

func TestNativeActualParseFailuresAreBalanced(t *testing.T) {
	api, ledger := auditedNativeAPI(t)
	ace := lifetimeACE()
	ace.Condition = Raw("(@User.Name === )")
	if _, err := api.compile(ace); err == nil {
		t.Fatal("malformed condition accepted")
	}
	assertBalanced(t, ledger, 1)
	if _, err := api.normalize("not a descriptor"); err == nil {
		t.Fatal("malformed SDDL accepted")
	}
	assertBalanced(t, ledger, 1)
}
