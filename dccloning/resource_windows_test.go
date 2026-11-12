//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	ad "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/registry"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/services"
)

type resourceCounts struct {
	Acquired    int `json:"acquired"`
	Released    int `json:"released"`
	Outstanding int `json:"outstanding"`
}

type ownerLedger struct {
	kind       string
	active     map[uintptr]bool
	acquired   int
	released   int
	violations []error
}

func (l *ownerLedger) acquire(id uintptr) {
	l.acquired++
	if id == 0 || l.active[id] {
		l.violations = append(l.violations, fmt.Errorf("%s: invalid or duplicate acquisition", l.kind))
	}
	if l.active == nil {
		l.active = make(map[uintptr]bool)
	}
	l.active[id] = true
}

// Refuse an unknown release so an ownership regression cannot double-free a
// native pointer or close an unrelated handle while running qualification.
func (l *ownerLedger) owns(id uintptr) bool {
	if !l.active[id] {
		l.violations = append(l.violations, fmt.Errorf("%s: release without ownership", l.kind))
		return false
	}
	return true
}

func (l *ownerLedger) release(id uintptr) {
	l.released++
	delete(l.active, id)
}

func (l *ownerLedger) counts() resourceCounts {
	return resourceCounts{Acquired: l.acquired, Released: l.released, Outstanding: len(l.active)}
}

func (l *ownerLedger) check() error {
	err := errors.Join(l.violations...)
	if l.acquired == 0 || l.acquired != l.released || len(l.active) != 0 {
		err = errors.Join(err, fmt.Errorf("%s: acquisition/release counts %+v", l.kind, l.counts()))
	}
	return err
}

type resourceLedger struct {
	role ownerLedger
	keys ownerLedger
	scm  ownerLedger
}

func trackResources(real nativeAPI) (nativeAPI, *resourceLedger) {
	l := &resourceLedger{role: ownerLedger{kind: "role buffers"}, keys: ownerLedger{kind: "registry keys"}, scm: ownerLedger{kind: "SCM handles"}}
	tracked := real
	tracked.getRole = func(server *string, level ad.DSROLE_PRIMARY_DOMAIN_INFO_LEVEL, out **byte) uint32 {
		status := real.getRole(server, level, out)
		if *out != nil {
			l.role.acquire(uintptr(unsafe.Pointer(*out)))
		}
		return status
	}
	tracked.freeRole = func(pointer unsafe.Pointer) {
		id := uintptr(pointer)
		if l.role.owns(id) {
			real.freeRole(pointer)
			l.role.release(id)
		}
	}
	tracked.openKey = func(parent registry.HKEY, name *string, options uint32, access registry.REG_SAM_FLAGS, out *registry.HKEY) foundation.WIN32_ERROR {
		status := real.openKey(parent, name, options, access, out)
		if status == 0 {
			l.keys.acquire(uintptr(*out))
		}
		return status
	}
	tracked.closeKey = func(key registry.HKEY) foundation.WIN32_ERROR {
		if !l.keys.owns(uintptr(key)) {
			return foundation.ERROR_INVALID_HANDLE
		}
		status := real.closeKey(key)
		if status == 0 {
			l.keys.release(uintptr(key))
		}
		return status
	}
	tracked.openSCM = func(host, database *string, rights uint32) (services.SC_HANDLE, error) {
		handle, err := real.openSCM(host, database, rights)
		if err == nil {
			l.scm.acquire(uintptr(handle))
		}
		return handle, err
	}
	tracked.closeSCM = func(handle services.SC_HANDLE) error {
		if !l.scm.owns(uintptr(handle)) {
			return syscall.Errno(foundation.ERROR_INVALID_HANDLE)
		}
		err := real.closeSCM(handle)
		if err == nil {
			l.scm.release(uintptr(handle))
		}
		return err
	}
	return tracked, l
}

type resourceCycle struct {
	Iteration int            `json:"iteration"`
	Entries   int            `json:"entries"`
	Complete  bool           `json:"complete"`
	Role      resourceCounts `json:"role_buffers"`
	Registry  resourceCounts `json:"registry_keys"`
	SCM       resourceCounts `json:"scm_handles"`
	Passed    bool           `json:"passed"`
	Error     string         `json:"error,omitempty"`
}

type resourceReport struct {
	SchemaVersion       int             `json:"schema_version"`
	Started             string          `json:"started"`
	Finished            string          `json:"finished"`
	Computer            string          `json:"computer"`
	Architecture        string          `json:"architecture"`
	GoVersion           string          `json:"go_version"`
	IterationsRequested int             `json:"iterations_requested"`
	IterationsCompleted int             `json:"iterations_completed"`
	Cycles              []resourceCycle `json:"cycles"`
	Passed              bool            `json:"passed"`
	Error               string          `json:"error,omitempty"`
}

func nativeResourceCycles(ctx context.Context, iterations int) resourceReport {
	report := resourceReport{
		SchemaVersion: 1, Started: time.Now().UTC().Format(time.RFC3339Nano),
		Architecture: runtime.GOARCH, GoVersion: runtime.Version(), IterationsRequested: iterations,
		Cycles: []resourceCycle{},
	}
	report.Computer, _ = os.Hostname()
	var runError error
	for iteration := 1; iteration <= iterations; iteration++ {
		api, ledger := trackResources(systemAPI())
		err := api.available(false)
		var result Result
		if err == nil {
			// This is the same core and native calls used by public Inspect.
			result, _, err = inspect(ctx, nativeMachine{api}, readList, "")
		}
		err = errors.Join(err, ledger.role.check(), ledger.keys.check(), ledger.scm.check(), context.Cause(ctx))
		if !result.Complete {
			err = errors.Join(err, ErrIncomplete)
		}
		cycle := resourceCycle{
			Iteration: iteration, Entries: len(result.Entries), Complete: result.Complete,
			Role: ledger.role.counts(), Registry: ledger.keys.counts(), SCM: ledger.scm.counts(), Passed: err == nil,
		}
		if err != nil {
			cycle.Error = err.Error()
			runError = err
		}
		report.Cycles = append(report.Cycles, cycle)
		if err != nil {
			break
		}
		report.IterationsCompleted++
	}
	report.Passed = runError == nil && report.IterationsCompleted == iterations
	if runError != nil {
		report.Error = runError.Error()
	}
	report.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	return report
}

// TestNativeResourceCycles is opt-in qualification on a parent-owned DC. It
// changes no AD/service/registry configuration. The caller supplies a new report
// path and bounds the process with -timeout 2m; context permits report cleanup
// before that deadline. Native synchronous calls cannot be cancelled mid-call.
func TestNativeResourceCycles(t *testing.T) {
	path := os.Getenv("ADSDK_CLONING_RESOURCE_REFERENCE")
	if path == "" {
		t.Skip("isolated DC resource qualification supplies output path")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("resource report path must be absolute")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	report := nativeResourceCycles(ctx, 100)
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = errors.Join(encoder.Encode(report), file.Close())
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("native resource qualification failed; report retained: %s", report.Error)
	}
}

func TestResourceTrackingRetainsFailedCloseAndRejectsUnknownRelease(t *testing.T) {
	closed := 0
	api, ledger := trackResources(nativeAPI{
		openSCM: func(*string, *string, uint32) (services.SC_HANDLE, error) { return 42, nil },
		closeSCM: func(services.SC_HANDLE) error {
			closed++
			return syscall.ERROR_ACCESS_DENIED
		},
	})
	handle, err := api.openSCM(nil, nil, services.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.closeSCM(handle); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
		t.Fatal(err)
	}
	if ledger.scm.counts() != (resourceCounts{Acquired: 1, Outstanding: 1}) || ledger.scm.check() == nil {
		t.Fatal("failed native close was counted as release")
	}
	if err := api.closeSCM(99); !errors.Is(err, syscall.Errno(foundation.ERROR_INVALID_HANDLE)) || closed != 1 {
		t.Fatalf("unknown handle reached native close: %v, calls %d", err, closed)
	}
}
