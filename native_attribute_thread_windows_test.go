//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/threading"
)

// A native BerElement belongs to the thread that starts attribute enumeration.
// Occupy the reader's old OS thread while the same reader goroutine resumes:
// without a scoped lock, real WinLDAP returns LDAP_LOCAL_ERROR from nextAttribute.
// With the lock, the holder uses another thread and enumeration stays together.
func TestNativeAttributeEnumerationSurvivesSchedulerHandoff(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for _, callerPinned := range []bool{false, true} {
		name := "unpinned-caller"
		if callerPinned {
			name = "already-pinned-caller"
		}
		t.Run(name, func(t *testing.T) {
			if callerPinned {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
			}
			fixture := newSearchWireFixture(t, nil)
			var counts searchNativeCounts
			api := countedSearchAPI(&counts)
			original := api
			var firstThread, resumedThread, holderThread uint32
			threads := make(map[string]uint32)
			api.firstAttribute = func(handle *ldap.LDAP, entry *ldap.LDAPMessage, cursor **ldap.BerElement) foundation.PWSTR {
				// Capture the actual native operation's thread, retaining any
				// enclosing SDK or caller lock when this observation lock ends.
				runtime.LockOSThread()
				firstThread = threading.GetCurrentThreadId()
				attribute := original.firstAttribute(handle, entry, cursor)
				runtime.UnlockOSThread()
				ready := make(chan uint32)
				release, stopped := make(chan struct{}), make(chan struct{})
				go func() {
					runtime.LockOSThread()
					defer runtime.UnlockOSThread()
					defer close(stopped)
					ready <- threading.GetCurrentThreadId()
					<-release
				}()
				t.Cleanup(func() {
					close(release)
					select {
					case <-stopped:
					case <-time.After(time.Second):
						t.Error("thread holder did not stop")
					}
				})
				holderThread = <-ready
				resumedThread = threading.GetCurrentThreadId()
				return attribute
			}
			api.values = func(handle *ldap.LDAP, entry *ldap.LDAPMessage, name string) **ldap.LDAP_BERVAL {
				threads["values"] = threading.GetCurrentThreadId()
				return original.values(handle, entry, name)
			}
			api.nextAttribute = func(handle *ldap.LDAP, entry *ldap.LDAPMessage, cursor *ldap.BerElement) foundation.PWSTR {
				threads["next"] = threading.GetCurrentThreadId()
				return original.nextAttribute(handle, entry, cursor)
			}
			api.getOption = func(handle *ldap.LDAP, option int32, out unsafe.Pointer) uint32 {
				if option == int32(ldap.LDAP_OPT_ERROR_NUMBER) {
					threads["error-query"] = threading.GetCurrentThreadId()
				}
				return original.getOption(handle, option, out)
			}
			api.berFree = func(cursor *ldap.BerElement, free int32) {
				threads["cursor-free"] = threading.GetCurrentThreadId()
				original.berFree(cursor, free)
			}
			// This checks thread ownership, so allow native loopback startup on
			// busy CI workers before the first attribute operation is reached.
			client := searchWireClientWithTimeout(t, fixture, api, 5*time.Second)
			root, err := client.RootDSE(context.Background(), RootDSEOptions{})
			t.Logf("first=%d resumed=%d holder=%d operations=%v attributes=%d remaining=%+v err=%v", firstThread, resumedThread, holderThread, threads, len(root.Attributes), counts, err)
			if err != nil {
				t.Fatalf("valid RootDSE failed after scheduling: %v", err)
			}
			if firstThread != resumedThread || firstThread == holderThread {
				t.Fatal("attribute reader left its owning OS thread")
			}
			for operation, thread := range threads {
				if thread != firstThread {
					t.Errorf("%s moved off the attribute cursor's owning thread", operation)
				}
			}
			if len(threads) != 4 || len(root.SupportedControls) != 1 || root.SupportedControls[0] != "1.2.840.113556.1.4.319" || counts != (searchNativeCounts{}) {
				t.Fatal("native result or ownership proof is incomplete")
			}
		})
	}
}
