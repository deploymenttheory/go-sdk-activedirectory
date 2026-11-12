//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"errors"
	"os"
	"testing"
	"unsafe"

	ad "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
)

// Exercise the actual local-role boundary on Windows CI hosts, including ARM64.
// Positive DC behavior is qualified separately in the disposable server lab.
func TestNativeNonDCPrerequisite(t *testing.T) {
	var buffer *byte
	status := ad.DsRoleGetPrimaryDomainInformation(nil, ad.DsRolePrimaryDomainInfoBasic, &buffer)
	if buffer != nil {
		defer ad.DsRoleFreeMemory(unsafe.Pointer(buffer))
	}
	if status != 0 || buffer == nil {
		t.Fatalf("independent local role query: status %d, buffer %p", status, buffer)
	}
	info := (*ad.DSROLE_PRIMARY_DOMAIN_INFO_BASIC)(unsafe.Pointer(buffer))
	if info.MachineRole == ad.DsRole_RoleBackupDomainController || info.MachineRole == ad.DsRole_RolePrimaryDomainController {
		t.Skip("positive DC execution belongs to the explicit lab qualification")
	}
	result, err := Inspect(context.Background())
	if !errors.Is(err, ErrNotDomainController) {
		t.Fatalf("local non-DC role %d: expected role prerequisite error, got %v", info.MachineRole, err)
	}
	if result.Role.MachineRole != uint32(info.MachineRole) || result.Complete || len(result.Entries) != 0 || result.DefaultListPath != "" || result.CustomListPath != "" {
		t.Fatalf("non-DC inspection must stop before inclusion-file discovery: %+v", result)
	}
	directory := t.TempDir()
	generated, err := Generate(context.Background(), GenerateOptions{Directory: directory, Overwrite: true})
	if !errors.Is(err, ErrNotDomainController) || generated.Outcome != NotWritten || generated.Result.Role.MachineRole != uint32(info.MachineRole) {
		t.Fatalf("non-DC generation must preserve the prerequisite and unwritten outcome: %+v, %v", generated, err)
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("non-DC generation created output or temporary files: %v, %v", files, err)
	}
	t.Logf("native local role %d rejected before inclusion-file discovery", info.MachineRole)
}
