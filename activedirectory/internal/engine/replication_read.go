package engine

import (
	"context"
	"errors"
	"fmt"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalReplicationReader struct {
	InternalDial func(context.Context, admodel.Config) (*Client, error)
	// InternalNative retains its historical name for injected readers. Production
	// calls supply the explicit backend dispatcher, without a platform fallback.
	InternalNative func(
		context.Context,
		admodel.Config,
		admodel.RootDSE,
		[]byte,
		admodel.InternalReplicationRequest,
	) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error)
}

// ReadReplicationPartners reads inbound synchronization and/or outbound
// notification metadata from every selected server. LDAP omission is returned
// as incomplete, not as proof of no outbound partners. RPC and LDAP reads are
// sequential observations, not an atomic snapshot. See docs/replication.md.
func ReadReplicationPartners(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationPartnerQuery,
) (admodel.ReplicationPartnersResult, error) {
	return InternalReadReplicationPartners(
		ctx,
		config,
		query,
		InternalReplicationReader{Dial, InternalReadReplicationBackend},
	)
}

func InternalReadReplicationPartners(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationPartnerQuery,
	reader InternalReplicationReader,
) (result admodel.ReplicationPartnersResult, err error) {
	if query.Direction > admodel.ReplicationBoth ||
		!admodel.InternalValidDirectoryText(query.PartitionDN) {
		return result, admodel.ErrInvalidReplicationQuery
	}
	request := admodel.InternalReplicationRequest{
		InternalPartition: query.PartitionDN,
		InternalOutbound:  query.Direction != admodel.ReplicationInbound,
	}
	if query.Direction != admodel.ReplicationOutbound {
		request.InternalKinds = []admodel.InternalReplicationInfo{
			admodel.InternalReplicationNeighbors,
		}
	}
	var servers []admodel.InternalReplicationServerRead
	result.Targets, servers, err = reader.InternalRead(ctx, config, query.Selection, request)
	for _, server := range servers {
		projected := admodel.ReplicationPartnerServer{
			Observation:     server.InternalObservation,
			Outbound:        server.InternalOutbound,
			OutboundObjects: server.InternalObjects,
		}
		if reply, ok := server.InternalReplies[admodel.InternalReplicationNeighbors]; ok {
			projected.Inbound = reply.InternalState()
			projected.Partners = append(projected.Partners, reply.InternalData.InternalPartners...)
		}
		projected.Partners = append(projected.Partners, server.InternalPartners...)
		result.Servers = append(result.Servers, projected)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

// ReadReplicationFailures preserves connection and link failures separately.
// A successful zero-count native response is a confirmed empty collection;
// failed reads retain their native error and any other successful categories.
func ReadReplicationFailures(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationFailureQuery,
) (result admodel.ReplicationFailuresResult, err error) {
	return InternalReadReplicationFailures(
		ctx,
		config,
		query,
		InternalReplicationReader{Dial, InternalReadReplicationBackend},
	)
}

func InternalReadReplicationFailures(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationFailureQuery,
	reader InternalReplicationReader,
) (result admodel.ReplicationFailuresResult, err error) {
	var servers []admodel.InternalReplicationServerRead
	result.Targets, servers, err = reader.InternalRead(
		ctx,
		config,
		query.Selection,
		admodel.InternalReplicationRequest{
			InternalKinds: []admodel.InternalReplicationInfo{
				admodel.InternalReplicationConnectFailures,
				admodel.InternalReplicationLinkFailures,
			},
		},
	)
	for _, server := range servers {
		connections, links := server.InternalReplies[admodel.InternalReplicationConnectFailures], server.InternalReplies[admodel.InternalReplicationLinkFailures]
		result.Servers = append(
			result.Servers,
			admodel.ReplicationFailureServer{
				Observation: server.InternalObservation,
				Connections: connections.InternalState(),
				Links:       links.InternalState(),
				Failures: append(
					connections.InternalData.InternalFailures,
					links.InternalData.InternalFailures...),
			},
		)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

// ReadReplicationQueue preserves native queue order (the first pending item
// is executing) and the native container's current-operation start time.
func ReadReplicationQueue(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationQueueQuery,
) (result admodel.ReplicationQueueResult, err error) {
	return InternalReadReplicationQueue(
		ctx,
		config,
		query,
		InternalReplicationReader{Dial, InternalReadReplicationBackend},
	)
}

func InternalReadReplicationQueue(
	ctx context.Context,
	config admodel.Config,
	query admodel.ReplicationQueueQuery,
	reader InternalReplicationReader,
) (result admodel.ReplicationQueueResult, err error) {
	var servers []admodel.InternalReplicationServerRead
	result.Targets, servers, err = reader.InternalRead(
		ctx,
		config,
		query.Selection,
		admodel.InternalReplicationRequest{
			InternalKinds: []admodel.InternalReplicationInfo{
				admodel.InternalReplicationPendingOperations,
			},
		},
	)
	for _, server := range servers {
		reply := server.InternalReplies[admodel.InternalReplicationPendingOperations]
		result.Servers = append(
			result.Servers,
			admodel.ReplicationQueueServer{
				Observation:             server.InternalObservation,
				State:                   reply.InternalState(),
				CurrentOperationStarted: reply.InternalData.InternalStarted,
				Operations:              reply.InternalData.InternalOperations,
			},
		)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

func (reader InternalReplicationReader) InternalRead(
	ctx context.Context,
	config admodel.Config,
	selection admodel.ReplicationSelection,
	request admodel.InternalReplicationRequest,
) (targets admodel.ReplicationTargets, servers []admodel.InternalReplicationServerRead, err error) {
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return targets, nil, err
	}
	if len(request.InternalKinds) != 0 {
		if err = internalReplicationAuthentication(config); err != nil {
			return targets, nil, err
		}
		if config.Backend == admodel.BackendPortable && internalPortableReplicationEnabled && selection.ServicePrincipals == nil {
			return targets, nil, fmt.Errorf("%w: portable RPC requires explicit per-target service identities", admodel.ErrInvalidConfig)
		}
	}
	targets, err = InternalResolveReplicationTargets(ctx, config, selection, reader.InternalDial)
	for _, endpoint := range targets.Servers {
		if cause := context.Cause(ctx); cause != nil {
			err = errors.Join(err, cause)
			break
		}
		serverRequest := request
		serverConfig, principals, targetErr := admodel.InternalReplicationTargetConfig(config, selection, endpoint, len(request.InternalKinds) != 0)
		serverRequest.InternalServicePrincipals = principals
		var server admodel.InternalReplicationServerRead
		if targetErr != nil {
			server = internalReplicationMissingIdentity(endpoint, request, targetErr)
		} else {
			server = reader.InternalServer(ctx, serverConfig, serverRequest)
		}
		servers = append(servers, server)
		err = errors.Join(err, server.InternalObservation.Error)
	}
	return targets, servers, err
}

func (reader InternalReplicationReader) InternalServer(
	ctx context.Context,
	config admodel.Config,
	request admodel.InternalReplicationRequest,
) (result admodel.InternalReplicationServerRead) {
	result.InternalObservation.Endpoint = config.Endpoint
	result.InternalReplies = make(
		map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply,
	)
	var combined, categoryErrors error
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	defer func() {
		combined = errors.Join(combined, context.Cause(ctx))
		if result.InternalReplies == nil {
			result.InternalReplies = make(
				map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply,
			)
		}
		for _, kind := range request.InternalKinds {
			if _, ok := result.InternalReplies[kind]; !ok {
				cause := combined
				if cause == nil {
					cause = admodel.ErrIncompleteResult
				}
				result.InternalReplies[kind] = admodel.InternalReplicationNativeReply{
					InternalErr: cause,
				}
			}
		}
		if request.InternalOutbound && !result.InternalOutbound.Requested {
			result.InternalOutbound = admodel.InternalReplicationState(combined)
		}
		for _, reply := range result.InternalReplies {
			categoryErrors = errors.Join(categoryErrors, reply.InternalErr)
		}
		combined = errors.Join(combined, categoryErrors)
		if combined != nil {
			result.InternalObservation.Error = &admodel.ReplicationReadError{
				Operation: "read replication diagnostics",
				Server:    config.Endpoint,
				Cause:     combined,
			}
		}
		result.InternalObservation.Complete = combined == nil
	}()
	client, err := reader.InternalDial(ctx, config)
	if err != nil {
		combined = err
		return result
	}
	defer func() { combined = errors.Join(combined, client.Close()) }()
	result.InternalObservation.RootDSE, err = client.RootDSE(ctx, admodel.RootDSEOptions{})
	combined = errors.Join(combined, err)
	if err != nil {
		return result
	}
	typeOfDirectory := result.InternalObservation.RootDSE.Capabilities().Type
	if typeOfDirectory == admodel.DirectoryUnknown {
		combined = admodel.ErrUnsupportedDirectory
		return result
	}
	if request.InternalOutbound {
		result.InternalPartners, result.InternalObjects, err = InternalReadReplicationOutbound(
			ctx,
			client,
			request.InternalPartition,
		)
		result.InternalOutbound = admodel.InternalReplicationState(err)
		result.InternalOutbound.Available = len(result.InternalPartners) > 0 || err == nil
		categoryErrors = errors.Join(categoryErrors, err)
	}
	if len(request.InternalKinds) == 0 {
		return result
	}
	var instance []byte
	if config.Backend == admodel.BackendPortable && request.InternalServicePrincipals != nil {
		if typeOfDirectory != admodel.DirectoryADDS {
			combined = errors.Join(combined, admodel.ErrUnsupportedDirectory)
			return result
		}
		var identity admodel.InternalReplicationServiceIdentity
		identity, err = internalReadReplicationServiceIdentity(ctx, client, config, result.InternalObservation.RootDSE, *request.InternalServicePrincipals)
		if err != nil {
			combined = errors.Join(combined, err)
			return result
		}
		request.InternalPortableIdentity = &identity
		request.InternalObserveRPC = func(observed admodel.ReplicationRPCProtection) {
			result.InternalObservation.RPCProtection = append(result.InternalObservation.RPCProtection, observed)
		}
		instance = identity.DSA.Bytes()
	} else if typeOfDirectory == admodel.DirectoryADLDS {
		instance, err = InternalReplicationInstanceGUID(
			ctx,
			client,
			result.InternalObservation.RootDSE,
		)
		if err != nil {
			combined = errors.Join(combined, err)
			return result
		}
	}
	result.InternalReplies, err = reader.InternalNative(
		ctx,
		config,
		result.InternalObservation.RootDSE,
		instance,
		request,
	)
	combined = errors.Join(combined, err)
	return result
}

func internalReplicationMissingIdentity(endpoint admodel.Endpoint, request admodel.InternalReplicationRequest, cause error) (result admodel.InternalReplicationServerRead) {
	result.InternalObservation.Endpoint = endpoint
	result.InternalObservation.Error = &admodel.ReplicationReadError{Operation: "select replication server identities", Server: endpoint, Cause: cause}
	result.InternalReplies = make(map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, len(request.InternalKinds))
	for _, kind := range request.InternalKinds {
		result.InternalReplies[kind] = admodel.InternalReplicationNativeReply{InternalErr: cause}
	}
	if request.InternalOutbound {
		result.InternalOutbound = admodel.InternalReplicationState(cause)
	}
	return result
}

func InternalReplicationInstanceGUID(
	ctx context.Context,
	client *Client,
	root admodel.RootDSE,
) ([]byte, error) {
	if root.DSServiceName == nil || *root.DSServiceName == "" {
		return nil, admodel.ErrIncompleteResult
	}
	result, err := client.Search(
		ctx,
		admodel.SearchOptions{
			Base:       *root.DSServiceName,
			Scope:      admodel.ScopeBase,
			Filter:     "(objectClass=nTDSDSA)",
			Properties: []string{"objectGUID"},
		},
	)
	if err != nil {
		return nil, err
	}
	if !result.Complete || len(result.Objects) != 1 {
		return nil, admodel.ErrIncompleteResult
	}
	values, state := result.Objects[0].Attribute("objectGUID")
	if state != admodel.AttributePresent || len(values) != 1 || len(values[0]) != 16 {
		return nil, admodel.ErrInvalidResult
	}
	return values[0], nil
}

func InternalReadReplicationOutbound(
	ctx context.Context,
	client *Client,
	partition string,
) (partners []admodel.ReplicationPartner, objects []admodel.Object, err error) {
	attribute := "msds-replalloutboundneighbors"
	if partition != "" {
		attribute = "msds-ncreploutboundneighbors"
	}
	err = InternalClientRead(client, ctx, func(bounded context.Context) error {
		var failures error
		var start uint64
		for {
			if cause := context.Cause(bounded); cause != nil {
				return errors.Join(failures, cause)
			}
			requested := attribute
			if start != 0 {
				requested = fmt.Sprintf("%s;range=%d-*", attribute, start)
			}
			attributes, readErr := client.session.InternalRangedBaseObject(
				bounded,
				partition,
				[]string{requested},
			)
			objects = append(
				objects,
				admodel.Object{
					DistinguishedName:   partition,
					Attributes:          attributes,
					RequestedProperties: []string{requested},
				},
			)
			values, next, terminal, rangeErr := admodel.InternalReplicationRange(
				attributes,
				attribute,
				start,
			)
			for _, value := range values {
				partner, decodeErr := admodel.InternalDecodeOutboundPartner(value)
				partners = append(partners, partner)
				failures = errors.Join(failures, decodeErr)
			}
			failures = errors.Join(failures, readErr, rangeErr)
			if failures != nil || terminal {
				return failures
			}
			if next > 1<<20 {
				return errors.Join(failures, admodel.ErrIncompleteResult)
			}
			start = next
		}
	})
	return partners, objects, err
}
