package activedirectory

import (
	"context"
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
	Required  DirectoryType
	Actual    DirectoryType
}

func (e *DirectoryCapabilityError) Error() string {
	return fmt.Sprintf("%s requires %s; connected server advertises %s", e.Operation, e.Required, e.Actual)
}

func (e *DirectoryCapabilityError) Unwrap() error { return ErrUnsupportedDirectory }

// DirectoryCapabilities retains all advertised OIDs, including unknown ones.
// Advertisements do not prove access rights or negotiated authentication.
type DirectoryCapabilities struct {
	Type DirectoryType
	OIDs []string
}

func (c DirectoryCapabilities) Has(oid string) bool { return slices.Contains(c.OIDs, oid) }

// RequireADDS checks the directory-type prerequisite for a named operation.
// Unknown servers fail closed. A nil error only satisfies this prerequisite.
func (c DirectoryCapabilities) RequireADDS(operation string) error {
	if c.Type != DirectoryADDS {
		return &DirectoryCapabilityError{Operation: operation, Required: DirectoryADDS, Actual: c.Type}
	}
	return nil
}

// Capabilities classifies this RootDSE projection. Check the RootDSE read error
// before relying on a potentially partial projection.
func (r RootDSE) Capabilities() DirectoryCapabilities {
	result := DirectoryCapabilities{OIDs: slices.Clone(r.SupportedCapabilities)}
	// LDS can also advertise the generic Active Directory OID.
	if result.Has(CapabilityADLDS) {
		result.Type = DirectoryADLDS
	} else if result.Has(CapabilityActiveDirectory) {
		result.Type = DirectoryADDS
	}
	return result
}

// Capabilities reads the selected server's directory-type advertisements.
func (c *Client) Capabilities(ctx context.Context) (DirectoryCapabilities, error) {
	var result DirectoryCapabilities
	err := c.read(ctx, func(bounded context.Context) error {
		attributes, readErr := c.session.baseObject(bounded, "", []string{"supportedCapabilities"})
		decoder := rootDSEDecoder{attributes: attributes}
		result = (RootDSE{SupportedCapabilities: decoder.texts("supportedCapabilities")}).Capabilities()
		return errors.Join(readErr, errors.Join(decoder.errors...))
	})
	return result, err
}

// RequireADDS reads capabilities and rejects LDS or an unknown server type
// before a caller attempts an AD DS-only operation.
func (c *Client) RequireADDS(ctx context.Context, operation string) error {
	capabilities, err := c.Capabilities(ctx)
	if err != nil {
		return err
	}
	return capabilities.RequireADDS(operation)
}
