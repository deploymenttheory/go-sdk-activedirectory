package activedirectory

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrNoDefaultPartition = errors.New("directory has no usable default naming context; set Config.Partition explicitly")
	ErrNotNamingContext   = errors.New("selected object is not a naming-context root")
)

// Partition is the naming-context root returned by the configured server.
// Attributes owns copied raw values. On error the result may be partial.
type Partition struct {
	DistinguishedName string
	InstanceType      uint32
	Attributes        map[string][][]byte
}

// Partition resolves Config.Partition, or the server's advertised
// defaultNamingContext if no explicit partition is configured. It validates
// the selected object using an authenticated base read. No naming context is
// substituted when the selected one is missing, inaccessible, or not a root.
// Dial does not perform this read; RootDSE needs no default partition.
func (c *Client) Partition(ctx context.Context) (Partition, error) {
	var result Partition
	err := c.read(ctx, func(bounded context.Context) error {
		base := c.config.Partition
		if base == "" {
			attributes, err := c.session.baseObject(bounded, "", []string{"defaultNamingContext"})
			decoder := rootDSEDecoder{attributes: attributes}
			name := decoder.text("defaultNamingContext")
			if err := errors.Join(err, errors.Join(decoder.errors...), context.Cause(bounded)); err != nil {
				return err
			}
			if name == nil || *name == "" {
				return ErrNoDefaultPartition
			}
			base = *name
		}
		if err := context.Cause(bounded); err != nil {
			return err
		}
		attributes, readErr := c.session.baseObject(bounded, base, []string{"distinguishedName", "instanceType"})
		result.Attributes = attributes
		decoder := rootDSEDecoder{attributes: attributes}
		name := decoder.text("distinguishedName")
		instanceType := decodeScalar(&decoder, "instanceType", parseUint32)
		if name != nil {
			result.DistinguishedName = *name
		}
		if instanceType != nil {
			result.InstanceType = *instanceType
		}
		if err := errors.Join(readErr, errors.Join(decoder.errors...)); err != nil {
			return err
		}
		if name == nil || *name == "" || instanceType == nil {
			return fmt.Errorf("%w: partition read omitted distinguishedName or instanceType", ErrInvalidResult)
		}
		// instanceType bit 0 identifies an NC head in AD DS and AD LDS.
		// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
		if *instanceType&1 == 0 {
			return ErrNotNamingContext
		}
		return nil
	})
	return result, err
}
