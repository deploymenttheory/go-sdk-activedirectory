package replication

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// internalServiceCreateReplicationLink resolves topology references before creating a site link or
// bridge under its selected transport.
func internalServiceCreateReplicationLink(c *Service,
	ctx context.Context,
	name string,
	transport admodel.ReplicationTransport,
	description *string,
	attributes map[string][]admodel.RawValue,
	identities []admodel.Identity,
	options admodel.ObjectMutationOptions,
	bridge bool,
) (admodel.ReplicationLinkMutationResult, error) {
	var result admodel.ReplicationLinkMutationResult
	if name == "" || !admodel.InternalValidDirectoryText(name) {
		return result, admodel.ErrInvalidValue
	}
	if options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	if err := admodel.InternalReplicationReferenceChangesValid(
		admodel.ReplicationReferenceChanges{Replace: identities},
	); err != nil {
		return result, err
	}
	if description != nil && !admodel.InternalValidDirectoryText(*description) {
		return result, admodel.ErrInvalidValue
	}
	if description != nil {
		for attribute := range attributes {
			if strings.EqualFold(attribute, "description") {
				return result, admodel.ErrInvalidObjectMutation
			}
		}
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	var configuration, parent string
	class, attr, refClass := "siteLink", "siteList", "site"
	if bridge {
		class, attr, refClass = "siteLinkBridge", "siteLinkList", "siteLink"
	}
	var values [][]byte
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err = admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if err != nil {
			return err
		}
		parent, err = admodel.InternalReplicationTransportParent(
			root,
			adengine.InternalClientConfig(c.engine()),
			configuration,
			transport,
		)
		if err != nil {
			return err
		}
		container, err := admodel.InternalTopologyResolveDN(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			parent,
			configuration,
			[]string{"objectClass"},
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyClass(
			*container.Object,
			"interSiteTransport",
		); err != nil {
			return err
		}
		refParent := "CN=Sites," + configuration
		if bridge {
			refParent = parent
		}
		values, err = admodel.InternalResolveReplicationReferences(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			configuration,
			refParent,
			refClass,
			identities,
			&result.References,
		)
		return err
	})
	if err != nil {
		return result, err
	}
	attrs := make(map[string][]admodel.RawValue, len(attributes)+2)
	for name, values := range attributes {
		attrs[name] = slices.Clone(values)
	}
	if description != nil {
		attrs["description"] = []admodel.RawValue{admodel.NewRawValue([]byte(*description))}
	}
	if len(values) > 0 {
		for _, value := range values {
			attrs[attr] = append(attrs[attr], admodel.NewRawValue(value))
		}
	}
	options.Partition = configuration
	options.Properties = admodel.InternalReplicationLinkProperties(options.Properties, bridge)
	parentIdentity, _ := admodel.IdentityByDN(parent)
	result.Mutation, err = adengine.InternalClientCreateObjectWithReadback(
		c.engine(),
		ctx,
		admodel.CreateObjectRequest{
			Parent:     parentIdentity,
			Class:      class,
			Name:       name,
			Attributes: attrs,
			Options:    options,
		},
		func(
			ctx context.Context,
			session admodel.InternalLdapWriteSession,
			root admodel.RootDSE,
			mutation *admodel.ObjectMutationResult,
			mods []admodel.InternalLdapAttributeModification,
		) error {
			plainMods := slices.DeleteFunc(
				slices.Clone(mods),
				func(mod admodel.InternalLdapAttributeModification) bool {
					return strings.EqualFold(mod.InternalAttribute, attr)
				},
			)
			identity, e := admodel.IdentityByDN(mutation.TargetDN)
			if e != nil {
				return errors.Join(admodel.ErrObjectReadback, e)
			}
			if e := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				identity,
				mutation,
				admodel.InternalObjectWriteProperties(options, plainMods),
				false,
			); e != nil {
				return e
			}
			if e := admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, mutation, plainMods, name); e != nil {
				return e
			}
			mutation.Verified = false
			limits, _ := admodel.InternalNormalizeReplicationReferenceLimits(
				admodel.ReplicationReferenceLimits{},
			)
			result.AfterReferences, e = admodel.InternalCollectReplicationReferences(
				ctx,
				session,
				*mutation.After,
				attr,
				limits,
			)
			if e != nil {
				return errors.Join(admodel.ErrObjectReadback, e)
			}
			if len(values) > 0 {
				if e := admodel.InternalReplicationReferenceVerify(
					ctx,
					result.AfterReferences,
					[]admodel.InternalLdapAttributeModification{
						{InternalOperation: 2, InternalAttribute: attr, InternalValues: values},
					},
					attr,
				); e != nil {
					return e
				}
			}
			mutation.Verified = true
			return nil
		},
	)
	return admodel.InternalReplicationLinkProject(result, configuration, bridge, err)
}

// CreateReplicationSiteLink creates a link under the requested transport after resolving its site
// identities. Omitted cost and replication frequency default to 100 and 180 minutes; request may
// supply a schedule and link options.
//
// Related cmdlet: New-ADReplicationSiteLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adreplicationsitelink?view=windowsserver2025-ps
func (c *Service) CreateReplicationSiteLink(
	ctx context.Context,
	request CreateReplicationSiteLinkRequest,
) (ReplicationLinkMutationResult, error) {
	if request.LinkOptions & ^admodel.ReplicationSiteLinkOptions(7) != 0 {
		return admodel.ReplicationLinkMutationResult{}, admodel.ErrReplicationTopology
	}
	attrs := map[string][]admodel.RawValue{}
	for name, values := range request.Attributes {
		if _, err := admodel.InternalTopologyValidateChanges(
			[]admodel.AttributeChange{
				{Attribute: name, Kind: admodel.AttributeSet, Values: values},
			},
			admodel.InternalReplicationLinkManaged(),
		); err != nil {
			return admodel.ReplicationLinkMutationResult{}, err
		}
		attrs[name] = slices.Clone(values)
	}
	cost, interval := int32(100), int32(180)
	if request.Cost != nil {
		cost = *request.Cost
	}
	if request.ReplicationFrequencyInMinutes != nil {
		interval = *request.ReplicationFrequencyInMinutes
	}
	changes, err := admodel.InternalReplicationLinkValues(&cost, &interval, request.Schedule, false)
	if err != nil {
		return admodel.ReplicationLinkMutationResult{}, err
	}
	for _, change := range changes {
		attrs[change.Attribute] = change.Values
	}
	attrs["options"] = []admodel.RawValue{
		admodel.NewRawValue([]byte(strconv.FormatUint(uint64(request.LinkOptions), 10))),
	}
	return internalServiceCreateReplicationLink(c,
		ctx,
		request.Name,
		request.Transport,
		request.Description,
		attrs,
		request.Sites,
		request.Options,
		false,
	)
}

// CreateReplicationSiteLinkBridge creates a bridge under the requested transport after resolving its
// site-link identities. Request supplies its name, description, optional raw attributes, and write
// controls.
//
// Related cmdlet: New-ADReplicationSiteLinkBridge.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adreplicationsitelinkbridge?view=windowsserver2025-ps
func (c *Service) CreateReplicationSiteLinkBridge(
	ctx context.Context,
	request CreateReplicationSiteLinkBridgeRequest,
) (ReplicationLinkMutationResult, error) {
	for name, values := range request.Attributes {
		if _, err := admodel.InternalTopologyValidateChanges(
			[]admodel.AttributeChange{
				{Attribute: name, Kind: admodel.AttributeSet, Values: values},
			},
			admodel.InternalReplicationLinkManaged(),
		); err != nil {
			return admodel.ReplicationLinkMutationResult{}, err
		}
	}
	return internalServiceCreateReplicationLink(c,
		ctx,
		request.Name,
		request.Transport,
		request.Description,
		request.Attributes,
		request.SiteLinks,
		request.Options,
		true,
	)
}

// internalServiceUpdateReplicationLink validates a link or bridge and applies attribute, option, and
// reference changes.
func internalServiceUpdateReplicationLink(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	changes []admodel.AttributeChange,
	references admodel.ReplicationReferenceChanges,
	set, clear uint32,
	bridge bool,
) (admodel.ReplicationLinkMutationResult, error) {
	var result admodel.ReplicationLinkMutationResult
	if err := admodel.InternalTopologyMutationInput(identity, options); err != nil {
		return result, err
	}
	if err := admodel.InternalReplicationReferenceChangesValid(references); err != nil {
		return result, err
	}
	var mods []admodel.InternalLdapAttributeModification
	var err error
	if len(changes) > 0 {
		mods, err = admodel.InternalObjectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err = internalServiceTopologyMutationRoot(c, ctx, options)
	if err != nil {
		return result, err
	}
	class, attr, refClass := "siteLink", "siteList", "site"
	if bridge {
		class, attr, refClass = "siteLinkBridge", "siteLinkList", "siteLink"
	}
	var configuration string
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalReplicationLinkProperties(options.Properties, bridge),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			configuration, err = admodel.InternalTopologyConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			)
			if err != nil {
				return err
			}
			transport, err := admodel.InternalReplicationObjectTransport(
				*observed.Object,
				configuration,
			)
			if err != nil {
				return err
			}
			parent, err := admodel.InternalReplicationTransportParent(
				root,
				adengine.InternalClientConfig(c.engine()),
				configuration,
				transport,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalTopologyDirectChild(
				*observed.Object,
				parent,
				class,
			); err != nil {
				return err
			}
			refParent := "CN=Sites," + configuration
			if bridge {
				refParent = parent
			}
			refMods, err := admodel.InternalReplicationReferenceMods(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				configuration,
				refParent,
				refClass,
				attr,
				references,
				&result.References,
			)
			if err != nil {
				return err
			}
			flags, err := admodel.InternalReplicationOptionsMods(*observed.Object, set, clear, 7)
			if err != nil {
				return err
			}
			mods = append(mods, flags...)
			plainMods := slices.Clone(mods)
			mods = append(mods, refMods...)
			if len(mods) == 0 {
				if options.ExpectedVersion != nil {
					return admodel.ErrObjectControlUnsupported
				}
				mutation.After = mutation.Before
				mutation.ReadbackComplete = true
				mutation.Verified = true
				return nil
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*mutation.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation:     admodel.InternalLdapWriteModify,
					InternalDn:            admodel.InternalObjectGUIDTarget(*mutation.TargetGUID),
					InternalModifications: mods,
					InternalControls:      controls,
				},
				false,
				mutation,
			); err != nil {
				return err
			}
			readOptions := options
			readOptions.Properties = admodel.InternalReplicationLinkProperties(
				readOptions.Properties,
				bridge,
			)
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalObjectWriteProperties(readOptions, plainMods),
				false,
			); err != nil {
				return err
			}
			if err := admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, mutation, plainMods, ""); err != nil {
				return err
			}
			if len(refMods) > 0 {
				mutation.Verified = false
				limits, _ := admodel.InternalNormalizeReplicationReferenceLimits(
					admodel.ReplicationReferenceLimits{},
				)
				result.AfterReferences, err = admodel.InternalCollectReplicationReferences(
					ctx,
					session,
					*mutation.After,
					attr,
					limits,
				)
				if err != nil {
					return errors.Join(admodel.ErrObjectReadback, err)
				}
				if err := admodel.InternalReplicationReferenceVerify(
					ctx,
					result.AfterReferences,
					refMods,
					attr,
				); err != nil {
					return err
				}
				mutation.Verified = true
			}
			return nil
		},
	)
	return admodel.InternalReplicationLinkProject(result, configuration, bridge, err)
}

// UpdateReplicationSiteLink changes a link's cost, frequency, schedule, options, and site references.
// Request selects which values and references to change; mutation and reference readback outcomes are
// retained.
//
// Related cmdlet: Set-ADReplicationSiteLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationsitelink?view=windowsserver2025-ps
func (c *Service) UpdateReplicationSiteLink(
	ctx context.Context,
	request UpdateReplicationSiteLinkRequest,
) (ReplicationLinkMutationResult, error) {
	if request.SetOptions&request.ClearOptions != 0 ||
		(request.SetOptions|request.ClearOptions)&^admodel.ReplicationSiteLinkOptions(7) != 0 {
		return admodel.ReplicationLinkMutationResult{}, admodel.ErrReplicationTopology
	}
	if len(request.Changes) > 0 {
		if _, err := admodel.InternalTopologyValidateChanges(
			request.Changes,
			admodel.InternalReplicationLinkManaged(),
		); err != nil {
			return admodel.ReplicationLinkMutationResult{}, err
		}
	}
	changes, err := admodel.InternalReplicationLinkValues(
		request.Cost,
		request.ReplicationFrequencyInMinutes,
		request.Schedule,
		request.ClearSchedule,
	)
	if err != nil {
		return admodel.ReplicationLinkMutationResult{}, err
	}
	changes = append(
		changes,
		admodel.InternalTopologyTextChange("description", request.Description)...)
	changes = append(changes, request.Changes...)
	return internalServiceUpdateReplicationLink(c,
		ctx,
		request.Identity,
		request.Options,
		changes,
		request.Sites,
		uint32(request.SetOptions),
		uint32(request.ClearOptions),
		false,
	)
}

// UpdateReplicationSiteLinkBridge changes a bridge's description, raw attributes, and site-link
// references. Reference identities are resolved before mutation and their observations remain
// available on error.
//
// Related cmdlet: Set-ADReplicationSiteLinkBridge.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationsitelinkbridge?view=windowsserver2025-ps
func (c *Service) UpdateReplicationSiteLinkBridge(
	ctx context.Context,
	request UpdateReplicationSiteLinkBridgeRequest,
) (ReplicationLinkMutationResult, error) {
	if len(request.Changes) > 0 {
		if _, err := admodel.InternalTopologyValidateChanges(
			request.Changes,
			admodel.InternalReplicationLinkManaged(),
		); err != nil {
			return admodel.ReplicationLinkMutationResult{}, err
		}
	}
	return internalServiceUpdateReplicationLink(c,
		ctx,
		request.Identity,
		request.Options,
		append(
			admodel.InternalTopologyTextChange("description", request.Description),
			request.Changes...),
		request.SiteLinks,
		0,
		0,
		true,
	)
}

// internalServiceDeleteReplicationLink validates a site link or bridge before a leaf deletion in the
// configuration partition.
func internalServiceDeleteReplicationLink(c *Service,
	ctx context.Context,
	identity admodel.Identity,
	options admodel.ObjectMutationOptions,
	bridge bool,
) (admodel.ObjectMutationResult, error) {
	if err := admodel.InternalTopologyMutationInput(identity, options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	defer cancel()
	_, options, err = internalServiceTopologyMutationRoot(c, ctx, options)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		identity,
		options,
		admodel.ResolveIdentityOptions{},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, result *admodel.ObjectMutationResult) error {
			configuration, err := admodel.InternalTopologyConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			)
			if err != nil {
				return err
			}
			transport, err := admodel.InternalReplicationObjectTransport(
				*observed.Object,
				configuration,
			)
			if err != nil {
				return err
			}
			parent, err := admodel.InternalReplicationTransportParent(
				root,
				adengine.InternalClientConfig(c.engine()),
				configuration,
				transport,
			)
			if err != nil {
				return err
			}
			class := "siteLink"
			if bridge {
				class = "siteLinkBridge"
			}
			if err := admodel.InternalTopologyDirectChild(
				*observed.Object,
				parent,
				class,
			); err != nil {
				return err
			}
			controls, err := admodel.InternalObjectWriteControls(
				root,
				adengine.InternalClientConfig(c.engine()).Endpoint,
				options,
				*result.TargetGUID,
				false,
			)
			if err != nil {
				return err
			}
			if err := admodel.InternalSubmitObjectWrite(
				ctx,
				session,
				admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete,
					InternalDn:        admodel.InternalObjectGUIDTarget(*result.TargetGUID),
					InternalControls:  controls,
				},
				false,
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

// DeleteReplicationSiteLink deletes the selected site-link object as a leaf. It does not delete
// referenced sites; options select the partition and write controls.
//
// Related cmdlet: Remove-ADReplicationSiteLink.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adreplicationsitelink?view=windowsserver2025-ps
func (c *Service) DeleteReplicationSiteLink(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteReplicationLink(c, ctx, identity, options, false)
}

// DeleteReplicationSiteLinkBridge deletes the selected bridge as a leaf without deleting referenced
// site links. The mutation result preserves write acceptance and deletion readback state.
//
// Related cmdlet: Remove-ADReplicationSiteLinkBridge.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adreplicationsitelinkbridge?view=windowsserver2025-ps
func (c *Service) DeleteReplicationSiteLinkBridge(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	return internalServiceDeleteReplicationLink(c, ctx, identity, options, true)
}
