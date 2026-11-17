package engine

import (
	"context"
	"errors"
	"fmt"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Partition resolves Config.Partition, or the server's advertised
// defaultNamingContext if no explicit partition is configured. It validates
// the selected object using an authenticated base read. No naming context is
// substituted when the selected one is missing, inaccessible, or not a root.
// Dial does not perform this read; RootDSE needs no default partition.
func (c *Client) Partition(ctx context.Context) (admodel.Partition, error) {
	var result admodel.Partition
	err := InternalClientRead(c, ctx, func(bounded context.Context) error {
		base := c.config.Partition
		if base == "" {
			attributes, err := c.session.InternalBaseObject(
				bounded,
				"",
				[]string{"defaultNamingContext"},
			)
			decoder := admodel.InternalRootDSEDecoder{InternalAttributes: attributes}
			name := decoder.InternalText("defaultNamingContext")
			if err := errors.Join(
				err,
				errors.Join(decoder.InternalErrors...),
				context.Cause(bounded),
			); err != nil {
				return err
			}
			if name == nil || *name == "" {
				return admodel.ErrNoDefaultPartition
			}
			base = *name
		}
		if err := context.Cause(bounded); err != nil {
			return err
		}
		attributes, readErr := c.session.InternalBaseObject(
			bounded,
			base,
			[]string{"distinguishedName", "instanceType"},
		)
		result.Attributes = attributes
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: attributes}
		name := decoder.InternalText("distinguishedName")
		instanceType := admodel.InternalDecodeScalar(
			&decoder,
			"instanceType",
			admodel.InternalParseUint32,
		)
		if name != nil {
			result.DistinguishedName = *name
		}
		if instanceType != nil {
			result.InstanceType = *instanceType
		}
		if err := errors.Join(readErr, errors.Join(decoder.InternalErrors...)); err != nil {
			return err
		}
		if name == nil || *name == "" || instanceType == nil {
			return fmt.Errorf(
				"%w: partition read omitted distinguishedName or instanceType",
				admodel.ErrInvalidResult,
			)
		}
		// instanceType bit 0 identifies an NC head in AD DS and AD LDS.
		// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
		if *instanceType&1 == 0 {
			return admodel.ErrNotNamingContext
		}
		return nil
	})
	return result, err
}
