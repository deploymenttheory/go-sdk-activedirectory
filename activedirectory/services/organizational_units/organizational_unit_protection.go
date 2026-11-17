package organizational_units

import (
	"context"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// SetOrganizationalUnitProtection enables/disables the reference ACL pattern.
// Enabling can add Everyone deny-delete-child on the parent, affecting sibling
// deletion permissions. Disabling changes only explicit protection rights on
// this OU. Inherited/unknown rules and the parent's ACL are never removed.
func (c *Service) SetOrganizationalUnitProtection(
	ctx context.Context,
	identity adshared.Identity,
	protect bool,
	options adshared.ObjectMutationOptions,
) (OUProtectionResult, error) {
	var result admodel.OUProtectionResult
	if err := admodel.InternalValidateObjectOptions(identity, options); err != nil {
		return result, err
	}
	var err error
	result.Object, err = adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		identity,
		options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, object *admodel.ObjectMutationResult) error {
			if _, err := admodel.InternalDecodeOrganizationalUnit(*resolved.Object); err != nil {
				return err
			}
			return admodel.InternalChangeOUProtection(
				ctx,
				session,
				root,
				adengine.InternalClientConfig(c.engine()),
				object,
				protect,
				options,
				&result,
			)
		},
	)
	return result, err
}
