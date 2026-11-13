package activedirectory

import (
	"context"
	"errors"
	"fmt"
)

type replicationInfo uint32

const (
	replicationNeighbors         replicationInfo = 0
	replicationConnectFailures   replicationInfo = 3
	replicationLinkFailures      replicationInfo = 4
	replicationPendingOperations replicationInfo = 5
)

type replicationNativeData struct {
	partners   []ReplicationPartner
	failures   []ReplicationFailure
	operations []ReplicationQueueOperation
	started    ReplicationTimestamp
}
type replicationNativeReply struct {
	data replicationNativeData
	err  error
}
type replicationRequest struct {
	kinds     []replicationInfo
	outbound  bool
	partition string
}
type replicationReader struct {
	dial   func(context.Context, Config) (*Client, error)
	native func(context.Context, Config, RootDSE, []byte, replicationRequest) (map[replicationInfo]replicationNativeReply, error)
}
type replicationServerRead struct {
	observation ReplicationServerObservation
	replies     map[replicationInfo]replicationNativeReply
	outbound    ReplicationQueryState
	partners    []ReplicationPartner
	objects     []Object
}

// ReadReplicationPartners reads inbound synchronization and/or outbound
// notification metadata from every selected server. LDAP omission is returned
// as incomplete, not as proof of no outbound partners. RPC and LDAP reads are
// sequential observations, not an atomic snapshot. See docs/replication.md.
func ReadReplicationPartners(ctx context.Context, config Config, query ReplicationPartnerQuery) (ReplicationPartnersResult, error) {
	return readReplicationPartners(ctx, config, query, replicationReader{Dial, readReplicationNative})
}
func readReplicationPartners(ctx context.Context, config Config, query ReplicationPartnerQuery, reader replicationReader) (result ReplicationPartnersResult, err error) {
	if query.Direction > ReplicationBoth || !validDirectoryText(query.PartitionDN) {
		return result, ErrInvalidReplicationQuery
	}
	request := replicationRequest{partition: query.PartitionDN, outbound: query.Direction != ReplicationInbound}
	if query.Direction != ReplicationOutbound {
		request.kinds = []replicationInfo{replicationNeighbors}
	}
	var servers []replicationServerRead
	result.Targets, servers, err = reader.read(ctx, config, query.Selection, request)
	for _, server := range servers {
		projected := ReplicationPartnerServer{Observation: server.observation, Outbound: server.outbound, OutboundObjects: server.objects}
		if reply, ok := server.replies[replicationNeighbors]; ok {
			projected.Inbound = reply.state()
			projected.Partners = append(projected.Partners, reply.data.partners...)
		}
		projected.Partners = append(projected.Partners, server.partners...)
		result.Servers = append(result.Servers, projected)
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

// ReadReplicationFailures preserves connection and link failures separately.
// A successful zero-count native response is a confirmed empty collection;
// failed reads retain their native error and any other successful categories.
func ReadReplicationFailures(ctx context.Context, config Config, query ReplicationFailureQuery) (result ReplicationFailuresResult, err error) {
	return readReplicationFailures(ctx, config, query, replicationReader{Dial, readReplicationNative})
}
func readReplicationFailures(ctx context.Context, config Config, query ReplicationFailureQuery, reader replicationReader) (result ReplicationFailuresResult, err error) {
	var servers []replicationServerRead
	result.Targets, servers, err = reader.read(ctx, config, query.Selection, replicationRequest{kinds: []replicationInfo{replicationConnectFailures, replicationLinkFailures}})
	for _, server := range servers {
		connections, links := server.replies[replicationConnectFailures], server.replies[replicationLinkFailures]
		result.Servers = append(result.Servers, ReplicationFailureServer{Observation: server.observation, Connections: connections.state(), Links: links.state(), Failures: append(connections.data.failures, links.data.failures...)})
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

// ReadReplicationQueue preserves native queue order (the first pending item
// is executing) and the native container's current-operation start time.
func ReadReplicationQueue(ctx context.Context, config Config, query ReplicationQueueQuery) (result ReplicationQueueResult, err error) {
	return readReplicationQueue(ctx, config, query, replicationReader{Dial, readReplicationNative})
}
func readReplicationQueue(ctx context.Context, config Config, query ReplicationQueueQuery, reader replicationReader) (result ReplicationQueueResult, err error) {
	var servers []replicationServerRead
	result.Targets, servers, err = reader.read(ctx, config, query.Selection, replicationRequest{kinds: []replicationInfo{replicationPendingOperations}})
	for _, server := range servers {
		reply := server.replies[replicationPendingOperations]
		result.Servers = append(result.Servers, ReplicationQueueServer{Observation: server.observation, State: reply.state(), CurrentOperationStarted: reply.data.started, Operations: reply.data.operations})
	}
	result.Complete = err == nil && result.Targets.Complete
	return result, err
}

func replicationState(err error) ReplicationQueryState {
	return ReplicationQueryState{Requested: true, Available: err == nil, Complete: err == nil, Error: err}
}

func (reply replicationNativeReply) state() ReplicationQueryState {
	state := replicationState(reply.err)
	state.Available = state.Available || len(reply.data.partners)+len(reply.data.failures)+len(reply.data.operations) > 0 || reply.data.started.Ticks != nil
	return state
}

func (reader replicationReader) read(ctx context.Context, config Config, selection ReplicationSelection, request replicationRequest) (targets ReplicationTargets, servers []replicationServerRead, err error) {
	config, err = config.normalized()
	if err != nil {
		return targets, nil, err
	}
	if len(request.kinds) != 0 && config.Authentication != AuthenticationNegotiate {
		return targets, nil, fmt.Errorf("%w: native replication RPC requires Negotiate authentication", ErrInvalidConfig)
	}
	targets, err = resolveReplicationTargets(ctx, config, selection, reader.dial)
	for _, endpoint := range targets.Servers {
		if cause := context.Cause(ctx); cause != nil {
			err = errors.Join(err, cause)
			break
		}
		serverConfig := config
		serverConfig.Endpoint = endpoint
		server := reader.server(ctx, serverConfig, request)
		servers = append(servers, server)
		err = errors.Join(err, server.observation.Error)
	}
	return targets, servers, err
}

func (reader replicationReader) server(ctx context.Context, config Config, request replicationRequest) (result replicationServerRead) {
	result.observation.Endpoint = config.Endpoint
	result.replies = make(map[replicationInfo]replicationNativeReply)
	var combined error
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	defer func() {
		combined = errors.Join(combined, context.Cause(ctx))
		if result.replies == nil {
			result.replies = make(map[replicationInfo]replicationNativeReply)
		}
		for _, kind := range request.kinds {
			if _, ok := result.replies[kind]; !ok {
				cause := combined
				if cause == nil {
					cause = ErrIncompleteResult
				}
				result.replies[kind] = replicationNativeReply{err: cause}
			}
		}
		if request.outbound && !result.outbound.Requested {
			result.outbound = replicationState(combined)
		}
		if combined != nil {
			result.observation.Error = &ReplicationReadError{Operation: "read replication diagnostics", Server: config.Endpoint, Cause: combined}
		}
		result.observation.Complete = combined == nil
	}()
	client, err := reader.dial(ctx, config)
	if err != nil {
		combined = err
		return result
	}
	defer func() { combined = errors.Join(combined, client.Close()) }()
	result.observation.RootDSE, err = client.RootDSE(ctx, RootDSEOptions{})
	combined = errors.Join(combined, err)
	if err != nil {
		return result
	}
	typeOfDirectory := result.observation.RootDSE.Capabilities().Type
	if typeOfDirectory == DirectoryUnknown {
		combined = ErrUnsupportedDirectory
		return result
	}
	if request.outbound {
		result.partners, result.objects, err = readReplicationOutbound(ctx, client, request.partition)
		result.outbound = replicationState(err)
		result.outbound.Available = len(result.partners) > 0 || err == nil
		combined = errors.Join(combined, err)
	}
	if len(request.kinds) == 0 {
		return result
	}
	var instance []byte
	if typeOfDirectory == DirectoryADLDS {
		instance, err = replicationInstanceGUID(ctx, client, result.observation.RootDSE)
		if err != nil {
			combined = errors.Join(combined, err)
			return result
		}
	}
	result.replies, err = reader.native(ctx, config, result.observation.RootDSE, instance, request)
	combined = errors.Join(combined, err)
	for _, reply := range result.replies {
		combined = errors.Join(combined, reply.err)
	}
	return result
}

func replicationInstanceGUID(ctx context.Context, client *Client, root RootDSE) ([]byte, error) {
	if root.DSServiceName == nil || *root.DSServiceName == "" {
		return nil, ErrIncompleteResult
	}
	result, err := client.Search(ctx, SearchOptions{Base: *root.DSServiceName, Scope: ScopeBase, Filter: "(objectClass=nTDSDSA)", Properties: []string{"objectGUID"}})
	if err != nil {
		return nil, err
	}
	if !result.Complete || len(result.Objects) != 1 {
		return nil, ErrIncompleteResult
	}
	values, state := result.Objects[0].Attribute("objectGUID")
	if state != AttributePresent || len(values) != 1 || len(values[0]) != 16 {
		return nil, ErrInvalidResult
	}
	return values[0], nil
}

func readReplicationOutbound(ctx context.Context, client *Client, partition string) (partners []ReplicationPartner, objects []Object, err error) {
	attribute := "msds-replalloutboundneighbors"
	if partition != "" {
		attribute = "msds-ncreploutboundneighbors"
	}
	err = client.read(ctx, func(bounded context.Context) error {
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
			attributes, readErr := client.session.rangedBaseObject(bounded, partition, []string{requested})
			objects = append(objects, Object{DistinguishedName: partition, Attributes: attributes, RequestedProperties: []string{requested}})
			values, next, terminal, rangeErr := replicationRange(attributes, attribute, start)
			for _, value := range values {
				partner, decodeErr := decodeOutboundPartner(value)
				partners = append(partners, partner)
				failures = errors.Join(failures, decodeErr)
			}
			failures = errors.Join(failures, readErr, rangeErr)
			if failures != nil || terminal {
				return failures
			}
			if next > 1<<20 {
				return errors.Join(failures, ErrIncompleteResult)
			}
			start = next
		}
	})
	return partners, objects, err
}
