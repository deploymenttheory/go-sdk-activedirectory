// Package dccloning discovers local domain-controller cloning exclusions and
// writes custom inclusion lists. Native execution requires Windows amd64 or
// arm64. Inclusion does not certify that an application supports cloning.
package dccloning

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const CustomFileName = "CustomDCCloneAllowList.xml"

var (
	ErrUnsupported         = errors.New("DC cloning inventory requires Windows amd64 or arm64 and the native APIs")
	ErrNotDomainController = errors.New("DC cloning inventory requires a local AD DS domain controller")
	ErrInvalidList         = errors.New("invalid DC cloning inclusion list")
	ErrInvalidPath         = errors.New("invalid DC cloning output directory")
	ErrIncomplete          = errors.New("DC cloning inventory is incomplete")
	ErrOutputExists        = errors.New("DC cloning inclusion file already exists")
	ErrPrecedence          = errors.New("a higher-priority custom inclusion location takes precedence")
)

// Kind distinguishes service key names and program display names in each view.
type Kind string

const (
	Service      Kind = "Service"
	Program      Kind = "Program"
	WoW64Program Kind = "WoW64Program"
)

// Entry is one installed item or inclusion record. Source and Location are
// diagnostic provenance and are not written into the inclusion XML.
type Entry struct {
	Name     string `json:"name"`
	Type     Kind   `json:"type"`
	Source   string `json:"source,omitempty"`
	Location string `json:"location,omitempty"`
}

// Role describes the local computer; MachineRole is the native DSROLE value.
type Role struct {
	MachineRole uint32 `json:"machine_role"`
	ReadOnly    bool   `json:"read_only"`
}

// Result retains valid partial entries when an operation fails. Complete means
// enumeration of observable sources finished, not that every ACL permitted
// discovery. SCM can silently omit services lacking query-status permission.
type Result struct {
	Entries              []Entry `json:"entries"`
	Role                 Role    `json:"role"`
	DefaultListPath      string  `json:"default_list_path"`
	CustomListPath       string  `json:"custom_list_path,omitempty"`
	Complete             bool    `json:"complete"`
	AuthorizationLimited bool    `json:"authorization_limited"`
}

// NativeError preserves direct Win32 status independently from XML/SDK errors.
type NativeError struct {
	Operation string
	Code      uint32
	Cause     error
}

func (e *NativeError) Error() string { return fmt.Sprintf("%s: Windows error %d", e.Operation, e.Code) }
func (e *NativeError) Unwrap() error { return e.Cause }

// GenerateOptions requires an explicit existing directory. Overwrite permits
// replacement of CustomFileName only; it does not bypass location precedence.
type GenerateOptions struct {
	Directory string
	Overwrite bool
}

type WriteOutcome string

const (
	NotWritten     WriteOutcome = "not_written"
	Written        WriteOutcome = "written"
	WriteUncertain WriteOutcome = "uncertain"
)

// Generated contains the default-only exclusions used for generation. Inspect
// instead subtracts both the default and selected custom lists. Empty results
// have Outcome NotWritten and leave an existing file untouched.
type Generated struct {
	Result  Result       `json:"result"`
	Path    string       `json:"path"`
	Outcome WriteOutcome `json:"outcome"`
}

// Inspect reads the local installed inventory and subtracts default and custom
// inclusions. Callers must check both the returned error and Complete.
func Inspect(ctx context.Context) (Result, error) { return inspectNative(ctx) }

// Generate recomputes exclusions against the default list only and writes the
// custom list at the explicit supported location. It does not retry a write.
func Generate(ctx context.Context, options GenerateOptions) (Generated, error) {
	if options.Directory == "" || strings.ContainsRune(options.Directory, 0) {
		return Generated{Outcome: NotWritten}, ErrInvalidPath
	}
	return generateNative(ctx, options)
}

type locations struct {
	defaultPath string
	directories []string // Resolved search-order prefix, duplicate paths retained.
	// next resolves one further candidate. Empty path with nil error ends the
	// search. It must release native resources before returning, even on error.
	next func(context.Context) (string, error)
}

type machine interface {
	role(context.Context) (Role, error)
	locations(context.Context) (locations, error)
	inventory(context.Context) ([]Entry, error)
	equal(string, string) (bool, error)
}

type fileReader func(string) ([]byte, error)

// A nonempty output directory selects default-only generation. Resolve only
// through that directory: lower-priority candidates cannot affect its output.
func inspect(ctx context.Context, m machine, read fileReader, outputDirectory string) (Result, locations, error) {
	r := Result{Entries: []Entry{}, AuthorizationLimited: true}
	if err := context.Cause(ctx); err != nil {
		return r, locations{}, err
	}
	role, err := m.role(ctx)
	r.Role = role
	if err != nil {
		return r, locations{}, err
	}
	if role.MachineRole != 4 && role.MachineRole != 5 {
		return r, locations{}, ErrNotDomainController
	}
	paths, err := m.locations(ctx)
	r.DefaultListPath = paths.defaultPath
	if err != nil {
		return r, paths, err
	}
	data, err := read(paths.defaultPath)
	if err != nil {
		return r, paths, fmt.Errorf("read default inclusion list: %w", err)
	}
	allowed, err := ParseDefaultAllowList(data)
	if err != nil {
		return r, paths, fmt.Errorf("default inclusion list: %w", err)
	}
	customPath, customEntries, err := selectCustomList(ctx, m, &paths, read, outputDirectory)
	r.CustomListPath = customPath
	if err != nil {
		return r, paths, err
	}
	allowed = append(allowed, customEntries...)
	installed, inventoryErr := m.inventory(ctx)
	r.Entries, err = exclude(installed, allowed, m.equal)
	err = errors.Join(inventoryErr, err, context.Cause(ctx))
	r.Complete = err == nil
	if err != nil {
		err = errors.Join(ErrIncomplete, err)
	}
	return r, paths, err
}

func selectCustomList(ctx context.Context, m machine, paths *locations, read fileReader, outputDirectory string) (string, []Entry, error) {
	var selected string
	for index := 0; ; index++ {
		if err := context.Cause(ctx); err != nil {
			return selected, nil, err
		}
		if index == len(paths.directories) {
			if paths.next == nil {
				break
			}
			directory, err := paths.next(ctx)
			if err != nil {
				return selected, nil, err
			}
			if directory == "" {
				break
			}
			paths.directories = append(paths.directories, directory)
		}
		directory := paths.directories[index]
		atOutput := false
		if outputDirectory != "" {
			var err error
			atOutput, err = m.equal(filepath.Clean(directory), outputDirectory)
			if err != nil {
				return selected, nil, err
			}
		}
		if selected == "" {
			path := filepath.Join(directory, CustomFileName)
			data, err := read(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return selected, nil, fmt.Errorf("read custom inclusion list: %w", err)
			}
			if err == nil {
				selected = path
				if outputDirectory == "" {
					entries, parseErr := ParseCustomAllowList(data)
					if parseErr != nil {
						return selected, nil, fmt.Errorf("custom inclusion list: %w", parseErr)
					}
					return selected, entries, nil
				}
			}
		}
		if atOutput {
			break
		}
	}
	return selected, nil, nil
}

func exclude(installed, allowed []Entry, equal func(string, string) (bool, error)) ([]Entry, error) {
	result := make([]Entry, 0, len(installed))
	for _, entry := range installed {
		included := false
		for _, permit := range allowed {
			if entry.Type != permit.Type {
				continue
			}
			match, err := equal(entry.Name, permit.Name)
			if err != nil {
				return result, err
			}
			if match {
				included = true
				break
			}
		}
		if !included {
			result = append(result, entry)
		}
	}
	return result, nil
}
