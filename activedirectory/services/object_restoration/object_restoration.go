package object_restoration

import (
	"context"
	"errors"
	"fmt"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DeletedObjects performs a scoped, paged search with critical visibility
// controls. Search.ResultLimit and partial results have ordinary Search
// semantics. Extra properties and deactivated links remain copied raw values;
// range responses are incomplete, never silently counted as full attributes.
//
// Related cmdlet: Get-ADObject.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject?view=windowsserver2025-ps
func (c *Service) DeletedObjects(
	ctx context.Context,
	query DeletedObjectQuery,
) (result DeletedObjectsResult, err error) {
	if err = query.Search.Validate(); err != nil {
		return result, err
	}
	for _, property := range query.Search.Properties {
		if property == "1.1" {
			return result, admodel.ErrInvalidProperty
		}
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	result.Source = adengine.InternalClientConfig(c.engine()).Endpoint
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		root, err := admodel.InternalRestorationRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()).Endpoint,
		)
		if err != nil {
			return err
		}
		controls, err := admodel.InternalRestorationControls(
			root,
			query.IncludeRecycled,
			query.IncludeDeactivatedLinks,
		)
		if err != nil {
			return err
		}
		options := query.Search
		var identity admodel.Identity
		if options.Base != "" {
			identity, err = admodel.IdentityByDN(options.Base)
			if err != nil {
				return err
			}
		}
		index, _, err := admodel.InternalIdentityPartition(
			identity,
			adengine.InternalClientConfig(c.engine()).Partition,
			root,
		)
		if err != nil {
			return err
		}
		result.Partition = root.NamingContexts[index]
		if options.Base == "" {
			options.Base = result.Partition
		}
		options.Properties = admodel.InternalRestorationProperties(options.Properties)
		if options.Filter == "" {
			options.Filter = "(isDeleted=TRUE)"
		} else {
			options.Filter = "(&(isDeleted=TRUE)" + options.Filter + ")"
		}
		var featureErr error
		result.Capabilities, featureErr = admodel.InternalRestorationFeatureState(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
		)
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			admodel.InternalControlledSearchSession{
				InternalDirectorySession: adengine.InternalClientSession(c.engine()),
				InternalControls:         controls,
			},
			options,
		)
		for _, object := range result.Observation.Objects {
			decoded := admodel.InternalDecodeDeletedObject(
				object,
				result.Capabilities.RecycleBinEnabled,
				!query.IncludeRecycled,
			)
			result.Objects = append(result.Objects, decoded)
			err = errors.Join(err, decoded.Error)
		}
		err = errors.Join(err, featureErr)
		result.Complete = result.Observation.Complete && err == nil
		return err
	})
	result.Complete = result.Complete && err == nil
	return result, err
}

// RestoreObject restores a deleted object using the requested Recycle Bin or legacy tombstone mode.
// Request may select a new name and parent; the result retains capability observations and the
// accepted or uncertain restoration outcome.
//
// Related cmdlet: Restore-ADObject.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/restore-adobject?view=windowsserver2025-ps
func (c *Service) RestoreObject(
	ctx context.Context,
	request RestoreObjectRequest,
) (result ObjectRestorationResult, err error) {
	result.Mode = request.Mode
	extra, err := internalServiceValidateRestoreRequest(request)
	if err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	result.Mutation.Source = adengine.InternalClientConfig(c.engine()).Endpoint
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	err = adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalLdapWriteSession)
		if !ok {
			return admodel.ErrUnsupported
		}
		root, err := admodel.InternalRestorationRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()).Endpoint,
		)
		if err != nil {
			return err
		}
		controls, err := admodel.InternalRestorationControls(root, false, false)
		if err != nil {
			return err
		}
		result.Capabilities, err = admodel.InternalRestorationFeatureState(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
		)
		if request.Mode == admodel.RestoreWithRecycleBin &&
			(err != nil || result.Capabilities.RecycleBinEnabled == nil || !*result.Capabilities.RecycleBinEnabled) {
			return errors.Join(admodel.ErrObjectRestoreFeature, err)
		}
		if cause := context.Cause(ctx); cause != nil {
			return fmt.Errorf("restore not submitted: %w", cause)
		}
		// Resolve through show-deleted first: the server excludes recycled
		// objects even when their isRecycled attribute is hidden by ACLs.
		resolved, properties, err := internalServiceResolveRestoreSource(c, ctx, session, root, request, controls, extra, &result)
		if err != nil {
			return err
		}
		decoded := result.Deleted
		parent := request.TargetParent
		if parent.Form() == 0 {
			if decoded.LastKnownParent == nil {
				return admodel.ErrAttributeUnavailable
			}
			parent, err = admodel.IdentityByDN(*decoded.LastKnownParent)
			if err != nil {
				return err
			}
		}
		result.Parent, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			parent,
			admodel.ResolveIdentityOptions{
				Partition:  resolved.Partition,
				Properties: []string{"objectGUID", "objectClass"},
			},
		)
		if err != nil {
			return err
		}
		name := request.NewName
		if name == nil {
			name = decoded.LastKnownRDN
		}
		if name == nil || *name == "" || !admodel.InternalValidDirectoryText(*name) {
			return errors.Join(admodel.ErrInvalidObjectRestore, admodel.ErrAttributeUnavailable)
		}
		dn, err := admodel.InternalParseIdentityDN(resolved.Object.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].InternalBinary {
			return admodel.ErrInvalidObjectRestore
		}
		for _, mod := range extra {
			if strings.EqualFold(mod.InternalAttribute, dn[0][0].InternalAttribute) {
				return fmt.Errorf(
					"%w: naming attribute is supplied by NewName",
					admodel.ErrInvalidObjectRestore,
				)
			}
		}
		result.Mutation.TargetDN = dn[0][0].InternalAttribute + "=" + admodel.InternalEscapeObjectName(
			*name,
		) + "," + result.Parent.Object.DistinguishedName
		conditional, err := admodel.InternalObjectWriteControls(
			root,
			adengine.InternalClientConfig(c.engine()).Endpoint,
			request.Options,
			*decoded.GUID,
			false,
		)
		if err != nil {
			return err
		}
		controls = append(controls, conditional...)
		mods := make([]admodel.InternalLdapAttributeModification, 0, 2+len(extra))
		mods = append(mods, []admodel.InternalLdapAttributeModification{
			{InternalOperation: 1, InternalAttribute: "isDeleted"},
			{
				InternalOperation: 2,
				InternalAttribute: "distinguishedName",
				InternalValues:    [][]byte{[]byte(result.Mutation.TargetDN)},
			},
		}...)
		mods = append(mods, extra...)
		if err := admodel.InternalSubmitObjectWrite(
			ctx,
			session,
			admodel.InternalLdapWriteRequest{
				InternalOperation:     admodel.InternalLdapWriteModify,
				InternalDn:            admodel.InternalObjectGUIDTarget(*decoded.GUID),
				InternalModifications: mods,
				InternalControls:      controls,
			},
			false,
			&result.Mutation,
		); err != nil {
			return err
		}
		if err := admodel.InternalObserveObjectWrite(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			admodel.InternalObjectGUIDIdentity(*decoded.GUID),
			&result.Mutation,
			properties,
			false,
		); err != nil {
			return err
		}
		return internalServiceVerifyRestoration(ctx, session, root, &result, extra)
	})
	return result, admodel.InternalClassifyObjectWriteError(err)
}

// internalServiceValidateRestoreRequest checks caller intent before a deleted
// object or target parent is read.
func internalServiceValidateRestoreRequest(request admodel.RestoreObjectRequest) ([]admodel.InternalLdapAttributeModification, error) {
	if request.Mode > admodel.RestoreLegacyTombstone ||
		(request.Mode == admodel.RestoreWithRecycleBin && len(request.Attributes) != 0) {
		return nil, admodel.ErrInvalidObjectRestore
	}
	extra, err := admodel.InternalRestoreAttributeModifications(request.Attributes)
	if err != nil {
		return nil, err
	}
	if err = admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return nil, err
	}
	if request.NewName != nil &&
		(*request.NewName == "" || !admodel.InternalValidDirectoryText(*request.NewName)) {
		return nil, admodel.ErrInvalidObjectRestore
	}
	if request.TargetParent.Form() != 0 {
		if err = admodel.InternalValidateIdentityOperation(
			request.TargetParent,
			admodel.ResolveIdentityOptions{Partition: request.Options.Partition},
		); err != nil {
			return nil, err
		}
	}
	return extra, nil
}

// internalServiceResolveRestoreSource preserves every controlled source
// observation and refuses recycled, protected or incorrectly scoped identities.
func internalServiceResolveRestoreSource(c *Service, ctx context.Context, session admodel.InternalLdapWriteSession,
	root admodel.RootDSE, request admodel.RestoreObjectRequest, controls []admodel.InternalLdapWriteControl,
	extra []admodel.InternalLdapAttributeModification, result *admodel.ObjectRestorationResult,
) (admodel.IdentityResult, []string, error) {
	deletedSession := admodel.InternalControlledSearchSession{InternalDirectorySession: session, InternalControls: controls}
	properties := admodel.InternalRestorationProperties(
		admodel.InternalObjectWriteProperties(request.Options, extra),
	)
	resolved, err := admodel.InternalResolveIdentitySession(
		ctx,
		deletedSession,
		adengine.InternalClientConfig(c.engine()),
		root,
		request.Identity,
		admodel.ResolveIdentityOptions{
			Partition:  request.Options.Partition,
			Properties: properties,
		},
	)
	result.Mutation.Partition = resolved.Partition
	result.Mutation.PreflightCandidates = resolved.Candidates
	if errors.Is(err, admodel.ErrDirectoryObjectNotFound) {
		// A second, read-only observation distinguishes a visible recycled
		// object from an unobservable/expired identity. Never retry a write.
		if recycledControls, controlErr := admodel.InternalRestorationControls(
			root,
			true,
			false,
		); controlErr == nil {
			recycled, readErr := admodel.InternalResolveIdentitySession(
				ctx,
				admodel.InternalControlledSearchSession{
					InternalDirectorySession: adengine.InternalClientSession(c.engine()),
					InternalControls:         recycledControls,
				},
				adengine.InternalClientConfig(c.engine()),
				root,
				request.Identity,
				admodel.ResolveIdentityOptions{
					Partition:  resolved.Partition,
					Properties: admodel.InternalRestorationProperties(nil),
				},
			)
			result.Mutation.PreflightCandidates = append(
				result.Mutation.PreflightCandidates,
				recycled.Candidates...)
			if readErr == nil {
				decoded := admodel.InternalDecodeDeletedObject(
					*recycled.Object,
					result.Capabilities.RecycleBinEnabled,
					false,
				)
				result.Deleted = &decoded
				return admodel.IdentityResult{}, nil, errors.Join(admodel.ErrObjectNotRestorable, decoded.Error)
			}
			return admodel.IdentityResult{}, nil, errors.Join(admodel.ErrDeletedObjectUnavailable, err, readErr)
		}
		return admodel.IdentityResult{}, nil, errors.Join(admodel.ErrDeletedObjectUnavailable, err)
	}
	if err != nil {
		return admodel.IdentityResult{}, nil, err
	}
	result.Mutation.Before = resolved.Object
	decoded := admodel.InternalDecodeDeletedObject(
		*resolved.Object,
		result.Capabilities.RecycleBinEnabled,
		true,
	)
	result.Deleted = &decoded
	if decoded.Error != nil || decoded.GUID == nil ||
		decoded.State == admodel.DeletedStateProtected ||
		(decoded.IsRecycled != nil && *decoded.IsRecycled && decoded.State != admodel.DeletedStateTombstone) ||
		(request.Mode == admodel.RestoreWithRecycleBin && decoded.State != admodel.DeletedStateDeleted) {
		return admodel.IdentityResult{}, nil, errors.Join(admodel.ErrObjectNotRestorable, decoded.Error)
	}
	if err := admodel.InternalValidateRestorationObject(
		*resolved.Object,
		resolved.Partition,
		root,
	); err != nil {
		return admodel.IdentityResult{}, nil, err
	}
	result.Mutation.TargetGUID = decoded.GUID
	if request.Identity.Form() == admodel.IdentityFormGUID &&
		request.Identity.String() != decoded.GUID.String() {
		return admodel.IdentityResult{}, nil, admodel.ErrInvalidResult
	}
	return resolved, properties, nil
}

// internalServiceVerifyRestoration checks the same GUID live observation, exact
// destination and explicit state flags before verifying supplied extra values.
func internalServiceVerifyRestoration(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE,
	result *admodel.ObjectRestorationResult, extra []admodel.InternalLdapAttributeModification,
) error {
	// An ordinary live-object search plus identical GUID and destination
	// verifies restoration, without treating omitted isDeleted as proof.
	actual, err := admodel.InternalParseIdentityDN(result.Mutation.After.DistinguishedName)
	wanted, _ := admodel.InternalParseIdentityDN(result.Mutation.TargetDN)
	if err != nil || !admodel.InternalSameIdentityDN(actual, wanted) {
		return admodel.ErrObjectVerification
	}
	for _, attribute := range []string{"isDeleted", "isRecycled"} {
		if values := result.Mutation.After.Values(
			attribute,
		); values.State == admodel.AttributePresent {
			value, err := values.Single()
			if err != nil {
				return errors.Join(admodel.ErrObjectVerification, err)
			}
			deleted, err := value.Bool()
			if err != nil || deleted {
				return errors.Join(admodel.ErrObjectVerification, err)
			}
		}
	}
	return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, &result.Mutation, extra, "")
}
