package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// CreateObject creates one schema-class instance under an explicitly resolved
// parent. Required/allowed attributes and security are validated by the server.
// ExpectedVersion is unsupported for creation: an assertion on the new entry
// cannot atomically guard its parent. The parent path is a preflight observation.
func (c *Client) CreateObject(
	ctx context.Context,
	request admodel.CreateObjectRequest,
) (admodel.ObjectMutationResult, error) {
	return InternalClientCreateObjectWithReadback(c, ctx, request, nil)
}

// Specialized linked-attribute workflows can verify bounded range reads under
// the same gate. The public generic operation retains its ordinary projection.
func InternalClientCreateObjectWithReadback(
	c *Client,
	ctx context.Context,
	request admodel.CreateObjectRequest,
	readback func(context.Context, admodel.InternalLdapWriteSession, admodel.RootDSE, *admodel.ObjectMutationResult, []admodel.InternalLdapAttributeModification) error,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Parent, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	if request.Options.ExpectedVersion != nil {
		return admodel.ObjectMutationResult{}, admodel.ErrObjectControlUnsupported
	}
	if !admodel.InternalObjectAttributeName(request.Class) || request.Name == "" ||
		!admodel.InternalValidDirectoryText(request.Name) {
		return admodel.ObjectMutationResult{}, admodel.ErrInvalidObjectMutation
	}
	mods, err := admodel.InternalCreateObjectAttributes(request.Attributes)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return InternalClientObjectMutation(
		c,
		ctx,
		request.Parent,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, resolved admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			naming, err := admodel.InternalObjectClassNamingAttribute(
				ctx,
				session,
				root,
				request.Class,
			)
			if err != nil {
				return err
			}
			for _, mod := range mods {
				if strings.EqualFold(mod.InternalAttribute, naming) {
					return fmt.Errorf(
						"%w: naming attribute is supplied by Name",
						admodel.ErrInvalidObjectMutation,
					)
				}
			}
			result.Before = nil // The resolved entry is the parent, not the new object.
			result.TargetGUID = nil
			result.TargetDN = naming + "=" + admodel.InternalEscapeObjectName(
				request.Name,
			) + "," + resolved.Object.DistinguishedName
			mods = append(
				mods,
				admodel.InternalLdapAttributeModification{
					InternalOperation: 0,
					InternalAttribute: "objectClass",
					InternalValues:    [][]byte{[]byte(request.Class)},
				},
				admodel.InternalLdapAttributeModification{
					InternalOperation: 0,
					InternalAttribute: naming,
					InternalValues:    [][]byte{[]byte(request.Name)},
				},
			)
			write := admodel.InternalLdapWriteRequest{
				InternalOperation:     admodel.InternalLdapWriteAdd,
				InternalDn:            result.TargetDN,
				InternalModifications: mods,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				false,
				result,
			); err != nil {
				return err
			}
			if readback != nil {
				return readback(ctx, session, root, result, mods)
			}
			identity, err := admodel.IdentityByDN(result.TargetDN)
			if err != nil {
				return errors.Join(admodel.ErrObjectReadback, err)
			}
			properties := append(
				admodel.InternalObjectWriteProperties(request.Options, mods),
				"distinguishedName",
			)
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				c.config,
				root,
				identity,
				result,
				properties,
				false,
			); err != nil {
				return err
			}
			if err := admodel.InternalVerifyObjectWrite(result, mods, request.Name); err != nil {
				return err
			}
			// Report the directory's own name for the object now that the readback
			// has been verified to be it. The composed name above addresses the
			// right entry but is not byte-identical to what the directory returns:
			// the schema spells the naming attribute "cn" and the directory
			// answers "CN". Callers store TargetDN and write it back into
			// DN-valued attributes such as manager or managedBy, where the
			// readback comparison is byte-exact, so handing back the submitted
			// spelling makes every one of those writes report an unverified
			// effect that in fact landed correctly.
			result.TargetDN = admodel.InternalObservedDistinguishedName(result.After)
			return nil
		},
	)
}

// UpdateObject submits one atomic LDAP Modify request. No permissive-modify
// control is used: adding an existing value or deleting a missing value retains
// the server's error. Clear deletes the entire attribute, including when that
// causes the server to report noSuchAttribute. No implicit read/merge/write.
func (c *Client) UpdateObject(
	ctx context.Context,
	request admodel.UpdateObjectRequest,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	mods, err := admodel.InternalObjectChanges(request.Changes)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return InternalClientObjectMutation(
		c,
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, _ admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			controls, err := admodel.InternalObjectWriteControls(
				root,
				c.config.Endpoint,
				request.Options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation:     admodel.InternalLdapWriteModify,
				InternalDn:            admodel.InternalObjectGUIDTarget(*result.TargetGUID),
				InternalModifications: mods,
				InternalControls:      controls,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				false,
				result,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				c.config,
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				admodel.InternalObjectWriteProperties(request.Options, mods),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWrite(result, mods, "")
		},
	)
}

func (c *Client) RenameObject(
	ctx context.Context,
	request admodel.RenameObjectRequest,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	if request.Name == "" || !admodel.InternalValidDirectoryText(request.Name) {
		return admodel.ObjectMutationResult{}, admodel.ErrInvalidObjectMutation
	}
	return InternalClientObjectMutation(
		c,
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, _ admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			dn, err := admodel.InternalParseIdentityDN(result.TargetDN)
			if err != nil || len(dn[0]) != 1 || dn[0][0].InternalBinary {
				return admodel.ErrInvalidObjectMutation
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				c.config.Endpoint,
				request.Options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			write := admodel.InternalLdapWriteRequest{
				InternalOperation: admodel.InternalLdapWriteRename,
				InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
				InternalNewRDN: dn[0][0].InternalAttribute + "=" + admodel.InternalEscapeObjectName(
					request.Name,
				),
				InternalDeleteOldRDN: true,
				InternalControls:     controls,
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				write,
				false,
				result,
			); err != nil {
				return err
			}
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				c.config,
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				admodel.InternalObjectWriteProperties(request.Options, nil),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWrite(result, nil, request.Name)
		},
	)
}

// DeleteObject defaults to leaf deletion. Recursive explicitly requests one
// critical AD tree-delete operation, which is not atomic across descendants.
// A server may delete only part of a large tree and report adminLimitExceeded;
// this method never repeats that request. Reconcile before further deletion.
func (c *Client) DeleteObject(
	ctx context.Context,
	request admodel.DeleteObjectRequest,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return InternalClientObjectMutation(
		c,
		ctx,
		request.Identity,
		request.Options,
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, _ admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			controls, err := admodel.InternalObjectWriteControls(
				root,
				c.config.Endpoint,
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
				c.config,
				root,
				admodel.InternalObjectGUIDIdentity(*result.TargetGUID),
				result,
				[]string{"objectGUID"},
				true,
			)
		},
	)
}

func InternalClientObjectMutation(c *Client,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	workflow admodel.InternalObjectMutationWorkflow,
) (admodel.ObjectMutationResult, error) {
	return InternalClientObjectMutationIdentity(c,
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{},
		workflow,
	)
}

// Typed workflows select their identity forms and preflight properties while
// retaining the common session gate, GUID addressing and outcome handling.
func InternalClientObjectMutationIdentity(c *Client,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	resolve admodel.ResolveIdentityOptions,
	workflow admodel.InternalObjectMutationWorkflow,
) (admodel.ObjectMutationResult, error) {
	resolve.Partition = options.Partition
	resolve.Properties = append(
		slices.Clone(resolve.Properties),
		"objectGUID",
		"uSNChanged",
		"objectClass",
	)
	result := admodel.ObjectMutationResult{}
	if c == nil || c.session == nil {
		return result, admodel.ErrClosed
	}
	result.Source = c.config.Endpoint
	err := InternalClientRead(c, ctx, func(ctx context.Context) error {
		session, ok := c.session.(admodel.InternalLdapWriteSession)
		if !ok {
			return admodel.ErrUnsupported
		}
		root, err := admodel.InternalReadIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		if root.Capabilities().Type == admodel.DirectoryADDS &&
			(c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269) {
			return admodel.ErrObjectWriteTarget
		}
		resolved, err := admodel.InternalResolveIdentitySession(
			ctx,
			session,
			c.config,
			root,
			identity,
			resolve,
		)
		result.Partition = resolved.Partition
		result.PreflightCandidates = resolved.Candidates
		if err != nil {
			return err
		}
		result.Before = resolved.Object
		result.TargetDN = resolved.Object.DistinguishedName
		value, err := resolved.Object.Values("objectGUID").Single()
		if err != nil {
			return errors.Join(admodel.ErrInvalidResult, err)
		}
		guid, err := value.GUID()
		if err != nil {
			return errors.Join(admodel.ErrInvalidResult, err)
		}
		result.TargetGUID = &guid
		return workflow(ctx, session, root, resolved, &result)
	})
	return result, admodel.InternalClassifyObjectWriteError(err)
}
