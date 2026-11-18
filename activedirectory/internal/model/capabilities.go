package model

import (
	"errors"
	"fmt"
	"slices"
)

const (
	CapabilityActiveDirectory = "1.2.840.113556.1.4.800"
	CapabilityADLDS           = "1.2.840.113556.1.4.1851"
)

// DirectoryType describes the server's advertised directory service.
type DirectoryType uint8

const (
	DirectoryUnknown DirectoryType = iota
	DirectoryADDS
	DirectoryADLDS
)

func (d DirectoryType) String() string {
	switch d {
	case DirectoryADDS:
		return "AD DS"
	case DirectoryADLDS:
		return "AD LDS"
	default:
		return "unknown directory type"
	}
}

var ErrUnsupportedDirectory = errors.New("operation requires a different directory type")

// DirectoryCapabilityError explains a directory-type prerequisite failure.
// It does not imply that an operation is implemented or that permission exists.
type DirectoryCapabilityError struct {
	Operation string
	// Required is DirectoryUnknown when either AD DS or AD LDS is acceptable.
	Required DirectoryType
	Actual   DirectoryType
}

func (e *DirectoryCapabilityError) Error() string {
	required := e.Required.String()
	if e.Required == DirectoryUnknown {
		required = "AD DS or AD LDS"
	}
	return fmt.Sprintf(
		"%s requires %s; connected server advertises %s",
		e.Operation,
		required,
		e.Actual,
	)
}

func (e *DirectoryCapabilityError) Unwrap() error { return ErrUnsupportedDirectory }

// Is retains legacy ErrUnsupported matching while Unwrap identifies the
// directory-type refusal. Check ErrUnsupportedDirectory before the broad sentinel.
func (e *DirectoryCapabilityError) Is(target error) bool { return target == ErrUnsupported }

// DirectoryCapabilities retains all advertised OIDs, including unknown ones.
// Advertisements do not prove access rights or negotiated authentication.
type DirectoryCapabilities struct {
	Type DirectoryType
	OIDs []string
}

func (c DirectoryCapabilities) Has(oid string) bool { return slices.Contains(c.OIDs, oid) }

// RequireAD checks that a server advertises AD DS or AD LDS. Unknown servers
// fail closed; success establishes only the directory-type prerequisite.
func (c DirectoryCapabilities) RequireAD(operation string) error {
	if c.Type != DirectoryADDS && c.Type != DirectoryADLDS {
		return &DirectoryCapabilityError{Operation: operation, Required: DirectoryUnknown, Actual: c.Type}
	}
	return nil
}

// RequireADDS checks the directory-type prerequisite for a named operation.
// Unknown servers fail closed. A nil error only satisfies this prerequisite.
func (c DirectoryCapabilities) RequireADDS(operation string) error {
	if c.Type != DirectoryADDS {
		return &DirectoryCapabilityError{
			Operation: operation,
			Required:  DirectoryADDS,
			Actual:    c.Type,
		}
	}
	return nil
}

// Capabilities classifies this RootDSE projection. Check the RootDSE read error
// before relying on a potentially partial projection.
func (r RootDSE) Capabilities() DirectoryCapabilities {
	result := DirectoryCapabilities{OIDs: slices.Clone(r.SupportedCapabilities)}
	// Prefer the LDS-specific indicator if a server advertises both OIDs.
	if result.Has(CapabilityADLDS) {
		result.Type = DirectoryADLDS
	} else if result.Has(CapabilityActiveDirectory) {
		result.Type = DirectoryADDS
	}
	return result
}
