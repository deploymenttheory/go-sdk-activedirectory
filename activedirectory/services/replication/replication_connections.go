package replication

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

// ReplicationConnection reads one replication connection and its referenced source and destination
// topology. Options select the configuration partition and additional properties; partial topology
// observations remain in the result.
//
// Related cmdlet: Get-ADReplicationConnection.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationconnection?view=windowsserver2025-ps
func (c *Service) ReplicationConnection(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (ReplicationConnectionResult, error) {
	var result admodel.ReplicationConnectionResult
	if err := admodel.InternalTopologyIdentity(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if err != nil {
			return err
		}
		options.Partition = configuration
		options.Properties = admodel.InternalReplicationConnectionProperties(options.Properties)
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if err != nil {
			return err
		}
		value, err := admodel.InternalDecodeReplicationConnection(
			*result.Observation.Object,
			configuration,
		)
		result.Connection = &value
		return err
	})
	return result, err
}

// ReplicationConnections searches below Sites by default. An explicit base must
// remain below that container. Raw and typed filters retain their usual rules.
//
// Related cmdlet: Get-ADReplicationConnection.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationconnection?view=windowsserver2025-ps
func (c *Service) ReplicationConnections(
	ctx context.Context,
	options adshared.SearchOptions,
) (ReplicationConnectionsResult, error) {
	var result admodel.ReplicationConnectionsResult
	normalized, err := admodel.InternalSearchOptionsNormalized(options)
	if err != nil {
		return result, err
	}
	err = adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		parent := "CN=Sites," + configuration
		if normalized.Base == "" {
			normalized.Base = parent
			normalized.Scope = admodel.ScopeSubtree
		}
		base, e := admodel.InternalParseIdentityDN(normalized.Base)
		scope, se := admodel.InternalParseIdentityDN(parent)
		if e != nil || se != nil || len(base) < len(scope) ||
			!admodel.InternalSameIdentityDN(base[len(base)-len(scope):], scope) {
			return admodel.ErrIdentityScope
		}
		normalized.Filter = "(&(objectClass=nTDSConnection)" + normalized.Filter + ")"
		normalized.Properties = admodel.InternalReplicationConnectionProperties(options.Properties)
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			normalized,
		)
		for _, object := range result.Observation.Objects {
			value, e := admodel.InternalDecodeReplicationConnection(object, configuration)
			result.Connections = append(result.Connections, value)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}

// UpdateReplicationConnection changes a replication connection's properties, schedule, source server,
// and raw attributes. Request selects write controls; the result preserves the mutation and topology
// readback outcomes.
//
// Related cmdlet: Set-ADReplicationConnection.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adreplicationconnection?view=windowsserver2025-ps
func (c *Service) UpdateReplicationConnection(
	ctx context.Context,
	request UpdateReplicationConnectionRequest,
) (ReplicationConnectionMutationResult, error) {
	const known = uint32(0x8000007f)
	var result admodel.ReplicationConnectionMutationResult
	if err := internalServiceValidateConnectionUpdate(request); err != nil {
		return result, err
	}
	changes, err := admodel.InternalReplicationLinkValues(
		nil,
		nil,
		request.Schedule,
		request.ClearSchedule,
	)
	if err != nil {
		return result, err
	}
	changes = append(
		changes,
		admodel.InternalTopologyTextChange("description", request.Description)...)
	changes = append(changes, request.Changes...)
	if request.Enabled != nil {
		text := "FALSE"
		if *request.Enabled {
			text = "TRUE"
		}
		changes = append(changes, admodel.InternalTopologyTextChange("enabledConnection", &text)...)
	}
	var mods []admodel.InternalLdapAttributeModification
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
	_, options, err := internalServiceTopologyMutationRoot(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = adengine.InternalClientObjectMutationIdentity(
		c.engine(),
		ctx,
		request.Identity,
		options,
		admodel.ResolveIdentityOptions{
			Properties: admodel.InternalReplicationConnectionProperties(options.Properties),
		},
		func(ctx context.Context, session admodel.InternalLdapWriteSession, root admodel.RootDSE, observed admodel.IdentityResult, mutation *admodel.ObjectMutationResult) error {
			configuration, err := admodel.InternalTopologyConfiguration(
				root,
				adengine.InternalClientConfig(c.engine()),
				options.Partition,
			)
			if err != nil {
				return err
			}
			destination, err := admodel.InternalReplicationConnectionParent(
				*observed.Object,
				configuration,
			)
			if err != nil {
				return err
			}
			if request.ReplicateFromDirectoryServer != nil {
				source, err := admodel.InternalReplicationConnectionSource(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					*request.ReplicateFromDirectoryServer,
					configuration,
					&result,
				)
				if err != nil {
					return err
				}
				if admodel.InternalTopologySameDN(source, destination) {
					return admodel.ErrReplicationTopology
				}
				mods = append(
					mods,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 2,
						InternalAttribute: "fromServer",
						InternalValues:    [][]byte{[]byte(source)},
					},
				)
			}
			if request.Transport != nil {
				dn, err := admodel.InternalReplicationTransportParent(
					root,
					adengine.InternalClientConfig(c.engine()),
					configuration,
					*request.Transport,
				)
				if err != nil {
					return err
				}
				result.Transport, err = admodel.InternalTopologyResolveDN(
					ctx,
					session,
					adengine.InternalClientConfig(c.engine()),
					root,
					dn,
					configuration,
					[]string{"objectClass"},
				)
				if err != nil {
					return err
				}
				if err := admodel.InternalTopologyClass(
					*result.Transport.Object,
					"interSiteTransport",
				); err != nil {
					return err
				}
				mods = append(
					mods,
					admodel.InternalLdapAttributeModification{
						InternalOperation: 2,
						InternalAttribute: "transportType",
						InternalValues: [][]byte{
							[]byte(result.Transport.Object.DistinguishedName),
						},
					},
				)
			}
			flags, err := admodel.InternalReplicationOptionsMods(
				*observed.Object,
				uint32(request.SetOptions),
				uint32(request.ClearOptions),
				known,
			)
			if err != nil {
				return err
			}
			mods = append(mods, flags...)
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
			readOptions.Properties = admodel.InternalReplicationConnectionProperties(
				readOptions.Properties,
			)
			if err := admodel.InternalObserveObjectWrite(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				admodel.InternalObjectGUIDIdentity(*mutation.TargetGUID),
				mutation,
				admodel.InternalObjectWriteProperties(readOptions, mods),
				false,
			); err != nil {
				return err
			}
			return admodel.InternalVerifyObjectWriteWithSchema(ctx, session, root, mutation, mods, "")
		},
	)
	if result.Mutation.After != nil {
		value, e := admodel.InternalDecodeReplicationConnection(
			*result.Mutation.After,
			options.Partition,
		)
		result.Connection = &value
		err = errors.Join(err, e)
	}
	return result, err
}

// internalServiceValidateConnectionUpdate rejects malformed references, option masks
// and managed raw attributes before a session or any directory observation.
func internalServiceValidateConnectionUpdate(request admodel.UpdateReplicationConnectionRequest) error {
	if err := admodel.InternalTopologyMutationInput(request.Identity, request.Options); err != nil {
		return err
	}
	if request.ReplicateFromDirectoryServer != nil {
		if err := admodel.InternalTopologyIdentity(
			*request.ReplicateFromDirectoryServer,
			admodel.ResolveIdentityOptions{},
		); err != nil {
			return err
		}
	}
	const known = uint32(0x8000007f)
	if request.SetOptions&request.ClearOptions != 0 ||
		uint32(request.SetOptions|request.ClearOptions)&^known != 0 {
		return admodel.ErrReplicationTopology
	}
	if len(request.Changes) > 0 {
		if _, err := admodel.InternalTopologyValidateChanges(
			request.Changes,
			admodel.InternalReplicationLinkManaged(),
		); err != nil {
			return err
		}
	}
	return nil
}
