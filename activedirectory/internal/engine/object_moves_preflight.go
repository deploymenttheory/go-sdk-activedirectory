package engine

import (
	"context"
	"errors"
	"slices"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Never hold both client gates. Endpoint preflights are sequential observations,
// not locks: the server remains authoritative for roles, access and constraints.
func internalMoveDestinationPreflight(
	ctx context.Context,
	destination *Client,
	request MoveObjectRequest,
	result *admodel.ObjectMoveResult,
) (root admodel.RootDSE, forest admodel.GUID, err error) {
	err = InternalClientRead(destination, ctx, func(ctx context.Context) error {
		var readErr error
		root, readErr = InternalMoveRoot(ctx, destination, &result.DestinationObservation, true)
		if readErr != nil {
			return readErr
		}
		result.Parent, readErr = admodel.InternalResolveIdentitySession(ctx, destination.session, destination.config, root, request.TargetParent,
			admodel.ResolveIdentityOptions{
				Partition:  request.DestinationPartition,
				Properties: []string{"objectGUID", "objectClass", "isDeleted", "isRecycled", "instanceType"},
			})
		result.DestinationPartition = result.Parent.Partition
		if readErr != nil {
			return readErr
		}
		if readErr = admodel.InternalValidateMoveParent(*result.Parent.Object, request.TargetParent); readErr != nil {
			return readErr
		}
		forest, readErr = InternalMoveDomainPreflight(ctx, destination, root, result.DestinationPartition, &result.DestinationObservation)
		result.DestinationObservation.Complete = readErr == nil
		return readErr
	})
	return root, forest, err
}

func (c *Client) internalMoveSourcePreflight(
	ctx context.Context,
	session admodel.InternalLdapWriteSession,
	root, destinationRoot admodel.RootDSE,
	destinationForest admodel.GUID,
	result *admodel.ObjectMoveResult,
) error {
	if admodel.InternalSameMoveDN(result.Mutation.Partition, result.DestinationPartition) {
		return admodel.ErrInvalidObjectMove
	}
	forest, err := InternalMoveDomainPreflight(ctx, c, root, result.Mutation.Partition, &result.SourceObservation)
	if err != nil {
		return err
	}
	if forest != destinationForest || root.RootDomainNamingContext == nil || destinationRoot.RootDomainNamingContext == nil ||
		!admodel.InternalSameMoveDN(*root.RootDomainNamingContext, *destinationRoot.RootDomainNamingContext) {
		return admodel.ErrMoveForest
	}
	if !slices.Contains(root.SupportedControls, admodel.InternalObjectCrossDomainMoveControl) {
		return admodel.ErrObjectControlUnsupported
	}
	security, ok := session.(admodel.InternalMoveSecuritySession)
	if !ok {
		return errors.Join(admodel.ErrMoveDelegation, admodel.ErrUnsupported)
	}
	result.Security, err = security.InternalMoveSecurity(ctx)
	if err != nil {
		return err
	}
	if !result.Security.Complete || !result.Security.Delegated || !strings.EqualFold(result.Security.Package, "Kerberos") {
		return admodel.ErrMoveDelegation
	}
	return nil
}

func (c *Client) internalMoveSourceOperation(
	ctx context.Context,
	request MoveObjectRequest,
	destinationRoot admodel.RootDSE,
	destinationForest admodel.GUID,
	result *admodel.ObjectMoveResult,
) error {
	session, ok := c.session.(admodel.InternalLdapWriteSession)
	if !ok {
		return admodel.ErrUnsupported
	}
	root, err := InternalMoveRoot(ctx, c, &result.SourceObservation, result.CrossDomain)
	if err != nil {
		return err
	}
	properties := append(
		admodel.InternalObjectWriteProperties(request.Options, nil),
		"systemFlags",
		"instanceType",
		"isDeleted",
		"isRecycled",
		"isCriticalSystemObject",
		"userAccountControl",
		"objectSid",
		"groupType",
	)
	resolved, err := admodel.InternalResolveIdentitySession(
		ctx,
		session,
		c.config,
		root,
		request.Identity,
		admodel.ResolveIdentityOptions{
			Partition:  request.Options.Partition,
			Properties: properties,
		},
	)
	result.Mutation.Partition = resolved.Partition
	result.Mutation.PreflightCandidates = resolved.Candidates
	if err != nil {
		return err
	}
	result.Mutation.Before = resolved.Object
	guid, err := admodel.InternalMoveObjectGUID(*resolved.Object)
	if err != nil {
		return err
	}
	result.Mutation.TargetGUID = &guid
	if request.Identity.Form() == admodel.IdentityFormGUID &&
		request.Identity.String() != guid.String() {
		return admodel.ErrInvalidResult
	}
	if result.CrossDomain {
		if err := c.internalMoveSourcePreflight(ctx, session, root, destinationRoot, destinationForest, result); err != nil {
			return err
		}
	} else {
		result.Parent, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			c.config,
			root,
			request.TargetParent,
			admodel.ResolveIdentityOptions{
				Partition: resolved.Partition,
				Properties: []string{
					"objectGUID",
					"objectClass",
					"isDeleted",
					"isRecycled",
					"instanceType",
				},
			},
		)
		result.DestinationPartition = result.Parent.Partition
		if err != nil {
			return err
		}
		if err := admodel.InternalValidateMoveParent(
			*result.Parent.Object,
			request.TargetParent,
		); err != nil {
			return err
		}
	}
	if err := admodel.InternalValidateMoveObject(
		*resolved.Object,
		*result.Parent.Object,
		root,
		resolved.Partition,
		result.CrossDomain,
	); err != nil {
		return err
	}
	parts, err := admodel.InternalSplitIdentityDN(resolved.Object.DistinguishedName, ',')
	if err != nil || len(parts) < 2 {
		return admodel.ErrInvalidObjectMove
	}
	result.Mutation.TargetDN = parts[0] + "," + result.Parent.Object.DistinguishedName
	controls, err := admodel.InternalObjectWriteControls(
		root,
		c.config.Endpoint,
		request.Options,
		guid,
		false,
	)
	if err != nil {
		return err
	}
	if result.CrossDomain {
		// Raw UTF-8 DNS hostname: no BER inner OCTET STRING and no NUL.
		controls = append(
			controls,
			admodel.InternalLdapWriteControl{
				InternalOid:      admodel.InternalObjectCrossDomainMoveControl,
				InternalCritical: true,
				InternalValue:    []byte(*destinationRoot.DNSHostName),
			},
		)
	}
	result.SourceObservation.Complete = true
	writeErr := admodel.InternalSubmitObjectWrite(
		ctx,
		session,
		admodel.InternalLdapWriteRequest{
			InternalOperation:    admodel.InternalLdapWriteRename,
			InternalDn:           admodel.InternalObjectGUIDTarget(guid),
			InternalNewRDN:       parts[0],
			InternalNewParent:    result.Parent.Object.DistinguishedName,
			InternalDeleteOldRDN: true,
			InternalControls:     controls,
		},
		false,
		&result.Mutation,
	)
	result.Mutation.PartialEffectsPossible = result.CrossDomain &&
		result.Mutation.State != admodel.ObjectWriteNotAttempted
	if writeErr != nil {
		return writeErr
	}
	if result.CrossDomain {
		return nil
	}
	if err := InternalObserveObjectMove(ctx, c, root, properties, result); err != nil {
		return errors.Join(admodel.ErrObjectReadback, err)
	}
	return nil
}
