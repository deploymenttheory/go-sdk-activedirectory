//go:build windows && (amd64 || arm64)

package dccloning

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/storage/filesystem"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/hypervisor"
	nativeio "github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/io"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/systeminformation"
	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

type configNativeAPI struct {
	name    func(systeminformation.COMPUTER_NAME_FORMAT, foundation.PWSTR, *uint32) error
	open    func(string, uint32, filesystem.FILE_SHARE_MODE, *security.SECURITY_ATTRIBUTES, filesystem.FILE_CREATION_DISPOSITION, filesystem.FILE_FLAGS_AND_ATTRIBUTES, foundation.HANDLE) (foundation.HANDLE, error)
	control func(foundation.HANDLE, uint32, []byte, []byte, *uint32, *nativeio.OVERLAPPED) error
	close   func(foundation.HANDLE) error
}

type nativeConfigEnvironment struct {
	nativeMachine
	host      configNativeAPI
	directory configDirectoryAPI
}

func generateConfigNative(ctx context.Context, options ConfigOptions) (Configured, error) {
	api := systemAPI()
	procs := []*win32.Proc{filesystem.Procs.MoveFileEx}
	if !options.Offline {
		if err := api.available(false); err != nil {
			return Configured{Outcome: NotWritten}, err
		}
		procs = append(procs, systeminformation.Procs.GetComputerNameEx, filesystem.Procs.CreateFile, nativeio.Procs.DeviceIoControl, foundation.Procs.CloseHandle)
	}
	for _, proc := range procs {
		if err := api.find(proc); err != nil {
			return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	environment := nativeConfigEnvironment{
		nativeMachine: nativeMachine{api},
		host:          configNativeAPI{name: systeminformation.GetComputerNameEx, open: filesystem.CreateFile, control: nativeio.DeviceIoControl, close: foundation.CloseHandle},
		directory: configDirectoryAPI{
			dial:     func(ctx context.Context, config ad.Config) (configConnection, error) { return ad.Dial(ctx, config) },
			discover: ad.DiscoverDomainController,
		},
	}
	publish := func(temporary, destination string, overwrite bool) error {
		flags := filesystem.MOVEFILE_WRITE_THROUGH
		if overwrite {
			flags |= filesystem.MOVEFILE_REPLACE_EXISTING
		}
		return nativeFailure("MoveFileExW(DCCloneConfig)", api.move(temporary, &destination, flags))
	}
	return generateConfiguration(ctx, options, environment, publish)
}

func (m nativeConfigEnvironment) prerequisites(ctx context.Context) (result ConfigPrerequisites, resultErr error) {
	result.Role, resultErr = m.role(ctx)
	if resultErr != nil {
		return result, resultErr
	}
	if result.Role.MachineRole != 4 && result.Role.MachineRole != 5 {
		return result, ErrNotDomainController
	}
	// Both writable DCs and RODCs are supported. A current generation-counter
	// read is additional host evidence beyond the reference cmdlet's checks.
	result.GenerationIDAvailable, resultErr = readCloneGeneration(ctx, m.host)
	if resultErr != nil {
		return result, resultErr
	}
	result.SourceHost, resultErr = cloneHostName(ctx, m.host.name)
	if resultErr != nil {
		return result, resultErr
	}
	if err := checkCloneDirectory(ctx, result.SourceHost, m.directory, &result); err != nil {
		return result, err
	}
	result.Applications, _, resultErr = inspect(ctx, m.nativeMachine, readList, "")
	if resultErr != nil {
		return result, resultErr
	}
	if !result.Applications.Complete || len(result.Applications.Entries) != 0 {
		return result, fmt.Errorf("%w: applications remain excluded or inventory is incomplete", ErrClonePrerequisite)
	}
	if err := context.Cause(ctx); err != nil {
		return result, err
	}
	result.Complete = true
	return result, nil
}

func readCloneGeneration(ctx context.Context, api configNativeAPI) (available bool, resultErr error) {
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	handle, err := api.open(`\\.\VmGenerationCounter`, uint32(foundation.GENERIC_READ|foundation.GENERIC_WRITE), filesystem.FILE_SHARE_READ|filesystem.FILE_SHARE_WRITE, nil, filesystem.OPEN_EXISTING, filesystem.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return false, errors.Join(ErrClonePrerequisite, nativeFailure("CreateFileW(VmGenerationCounter)", err))
	}
	if handle == 0 || handle == ^foundation.HANDLE(0) {
		return false, fmt.Errorf("%w: missing generation-counter handle", ErrIncomplete)
	}
	defer func() {
		resultErr = errors.Join(resultErr, nativeFailure("CloseHandle(VmGenerationCounter)", api.close(handle)))
	}()
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	var generation [16]byte
	var returned uint32
	// Polling (no input) returns the current value. The event form would wait
	// for a generation change and is inappropriate for a preparation check.
	if err := api.control(handle, hypervisor.IOCTL_VMGENCOUNTER_READ, nil, generation[:], &returned, nil); err != nil {
		return false, nativeFailure("DeviceIoControl(VMGENCOUNTER_READ)", err)
	}
	if returned != uint32(len(generation)) {
		return false, fmt.Errorf("%w: generation-counter byte count %d", ErrIncomplete, returned)
	}
	return true, context.Cause(ctx)
}

func cloneHostName(ctx context.Context, call func(systeminformation.COMPUTER_NAME_FORMAT, foundation.PWSTR, *uint32) error) (string, error) {
	buffer := make([]uint16, 256)
	for attempts := 0; attempts < 4; attempts++ {
		if err := context.Cause(ctx); err != nil {
			return "", err
		}
		size := uint32(len(buffer))
		err := call(systeminformation.ComputerNameDnsFullyQualified, &buffer[0], &size)
		if errors.Is(err, syscall.ERROR_MORE_DATA) && size > uint32(len(buffer)) && size <= 4096 {
			buffer = make([]uint16, size)
			continue
		}
		if err != nil {
			return "", nativeFailure("GetComputerNameExW", err)
		}
		if size == 0 || size >= uint32(len(buffer)) || buffer[size] != 0 {
			return "", fmt.Errorf("%w: invalid local DNS hostname length/terminator", ErrIncomplete)
		}
		return checkedUTF16(buffer[:size])
	}
	return "", fmt.Errorf("%w: unstable local DNS hostname", ErrIncomplete)
}

func (m nativeConfigEnvironment) configDirectories(ctx context.Context) ([]string, error) {
	working, err := m.parameterDirectory(ctx, "DSA Working Directory")
	if err != nil {
		return nil, err
	}
	windows, err := nativeDirectory(m.api.windowsDirectory)
	if err != nil {
		return nil, nativeFailure("GetWindowsDirectoryW", err)
	}
	directories := []string{working, filepath.Join(windows, "NTDS")}
	roots, err := m.driveRoots(ctx)
	if err != nil {
		return directories, err
	}
	sort.Strings(roots)
	for _, root := range roots {
		if err := context.Cause(ctx); err != nil {
			return directories, err
		}
		driveType := m.api.driveType(&root)
		if driveType == 0 {
			return directories, fmt.Errorf("%w: unknown clone configuration drive type", ErrIncomplete)
		}
		if driveType != 2 { // DRIVE_REMOVABLE
			continue
		}
		var flags uint32
		if err := m.api.volume(&root, nil, 0, nil, nil, &flags, nil, 0); err != nil {
			return directories, nativeFailure("GetVolumeInformationW(clone location)", err)
		}
		if flags&0x80000 == 0 { // FILE_READ_ONLY_VOLUME
			directories = append(directories, root)
		}
	}
	return directories, nil
}
