package organizational_units

import (
	"context"
	"errors"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// CreateOrganizationalUnit uses generic schema-class creation, then protection.
// The add and subsequent parent/OU ACL writes are not a transaction. A returned
// error can therefore accompany an accepted Add or parent ACL update.
//
// Related cmdlet: New-ADOrganizationalUnit.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adorganizationalunit?view=windowsserver2025-ps
func (c *Service) CreateOrganizationalUnit(
	ctx context.Context,
	request CreateOrganizationalUnitRequest,
) (OrganizationalUnitMutationResult, error) {
	var result admodel.OrganizationalUnitMutationResult
	changes, err := admodel.InternalOuPropertyChanges(request.Properties)
	if err != nil {
		return result, err
	}
	attributes := make(map[string][]admodel.RawValue, len(request.Attributes)+len(changes))
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	for _, change := range changes {
		for name := range attributes {
			if strings.EqualFold(name, change.Attribute) {
				return result, admodel.ErrInvalidObjectMutation
			}
		}
		attributes[change.Attribute] = change.Values
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	parent := request.Parent
	if parent.Form() == 0 {
		if c.engine() == nil {
			return result, admodel.ErrClosed
		}
		root, readErr := c.engine().RootDSE(ctx, admodel.RootDSEOptions{})
		if readErr != nil {
			return result, readErr
		}
		path := request.Options.Partition
		if path == "" {
			path = adengine.InternalClientConfig(c.engine()).Partition
		}
		if path == "" && root.DefaultNamingContext != nil {
			path = *root.DefaultNamingContext
		}
		if path == "" {
			return result, admodel.ErrNoDefaultPartition
		}
		parent, err = admodel.IdentityByDN(path)
		if err != nil {
			return result, err
		}
	}
	options := request.Options
	options.Properties = admodel.InternalOrganizationalUnitProperties(options.Properties)
	result.Object, err = c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: "organizationalUnit", Name: request.Name, Attributes: attributes, Options: options})
	if result.Object.After != nil {
		unit, decodeErr := admodel.InternalDecodeOrganizationalUnit(*result.Object.After)
		result.Unit = &unit
		err = errors.Join(err, decodeErr)
	}
	if err != nil {
		return result, err
	}
	protect := request.ProtectedFromAccidentalDeletion == nil ||
		*request.ProtectedFromAccidentalDeletion
	result.Protection, err = c.SetOrganizationalUnitProtection(
		ctx,
		admodel.InternalObjectGUIDIdentity(*result.Object.TargetGUID),
		protect,
		admodel.ObjectMutationOptions{Partition: result.Object.Partition},
	)
	if result.Unit != nil {
		result.Unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
	}
	return result, err
}

// UpdateOrganizationalUnit submits attribute changes in one strict Modify. An
// optional protection change follows; per-step outcomes survive later errors.
//
// Related cmdlet: Set-ADOrganizationalUnit.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adorganizationalunit?view=windowsserver2025-ps
func (c *Service) UpdateOrganizationalUnit(
	ctx context.Context,
	request UpdateOrganizationalUnitRequest,
) (OrganizationalUnitMutationResult, error) {
	var result admodel.OrganizationalUnitMutationResult
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	changes, err := admodel.InternalOuPropertyChanges(request.Properties)
	if err != nil {
		return result, err
	}
	changes = append(changes, request.Changes...)
	if len(changes) == 0 && request.ProtectedFromAccidentalDeletion == nil {
		return result, admodel.ErrInvalidObjectMutation
	}
	var mods []admodel.InternalLdapAttributeModification
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	if request.ProtectedFromAccidentalDeletion != nil && request.Options.ExpectedVersion != nil &&
		len(mods) > 0 {
		return result, admodel.ErrObjectControlUnsupported
	}
	result.Object, err = adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, object *admodel.ObjectMutationResult) error {
			if _, err := admodel.InternalDecodeOrganizationalUnit(*resolved.Object); err != nil {
				return err
			}
			if len(mods) > 0 {
				controls, err := admodel.InternalObjectWriteControls(
					root,
					adengine.InternalClientConfig(c.engine()).Endpoint,
					request.Options,
					*object.TargetGUID,
					false,
				)
				if err != nil {
					return err
				}
				write := admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*object.TargetGUID),
					InternalModifications: mods,
					InternalControls:      controls,
				}
				if err := admodel.InternalSubmitObjectWrite(
					ctx,
					session,
					write,
					false,
					object,
				); err != nil {
					return err
				}
				options := request.Options
				options.Properties = admodel.InternalOrganizationalUnitProperties(
					options.Properties,
				)
				if err := admodel.InternalObserveObjectWrite(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					admodel.InternalObjectGUIDIdentity(*object.TargetGUID),
					object,
					admodel.InternalObjectWriteProperties(options, mods),
					false,
				); err != nil {
					return err
				}
				if err := admodel.InternalVerifyObjectWrite(object, mods, ""); err != nil {
					return err
				}
			}
			if request.ProtectedFromAccidentalDeletion != nil {
				return admodel.InternalChangeOUProtection(
					ctx,
					session,
					root,
					adengine.InternalClientConfig(c.engine()),
					object,
					*request.ProtectedFromAccidentalDeletion,
					request.Options,
					&result.Protection,
				)
			}
			return nil
		},
	)
	if result.Object.After != nil {
		unit, decodeErr := admodel.InternalDecodeOrganizationalUnit(*result.Object.After)
		unit.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Unit = &unit
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// DeleteOrganizationalUnit never disables protection. Recursive intent can
// remove protected descendants of an unprotected target, as in the reference.
//
// Related cmdlet: Remove-ADOrganizationalUnit.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adorganizationalunit?view=windowsserver2025-ps
func (c *Service) DeleteOrganizationalUnit(
	ctx context.Context,
	request DeleteOrganizationalUnitRequest,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return adengine.InternalClientObjectMutation(
		c.engine(),
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			if _, err := admodel.InternalDecodeOrganizationalUnit(*resolved.Object); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				request.Options,
				*result.TargetGUID,
				request.Recursive,
			)
			if err != nil {
				return err
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteDelete,
				InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
				InternalControls:  controls,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				request.Recursive,
				result,
			); err != nil {
				return err
			}
			return admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}
