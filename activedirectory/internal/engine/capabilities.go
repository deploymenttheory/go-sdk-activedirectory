package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Capabilities reads the selected server's directory-type advertisements.
func (c *Client) Capabilities(ctx context.Context) (admodel.DirectoryCapabilities, error) {
	var result admodel.DirectoryCapabilities
	err := InternalClientRead(c, ctx, func(bounded context.Context) error {
		attributes, readErr := c.session.InternalBaseObject(
			bounded,
			"",
			[]string{"supportedCapabilities"},
		)
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: attributes}
		result = (admodel.RootDSE{SupportedCapabilities: decoder.InternalTexts("supportedCapabilities")}).Capabilities()
		return errors.Join(readErr, errors.Join(decoder.InternalErrors...))
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
