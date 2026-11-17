package engine

import (
	"context"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// ResolveIdentity resolves only on this authenticated connection, with no
// discovery, referral chasing, credential forwarding or fallback partition.
// All reads share one timeout. Errors retain native/permission/cleanup details;
// an incomplete single match is never treated as a unique object.
func (c *Client) ResolveIdentity(
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ResolveIdentityOptions,
) (admodel.IdentityResult, error) {
	var result admodel.IdentityResult
	if c == nil || c.session == nil {
		return result, admodel.ErrClosed
	}
	if err := admodel.InternalValidateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	result.Source = c.config.Endpoint
	err := InternalClientRead(c, ctx, func(bounded context.Context) error {
		root, readErr := admodel.InternalReadIdentityRoot(bounded, c.session)
		if readErr != nil {
			return readErr
		}
		result, readErr = admodel.InternalResolveIdentitySession(
			bounded,
			c.session,
			c.config,
			root,
			identity,
			options,
		)
		return readErr
	})
	return result, err
}
