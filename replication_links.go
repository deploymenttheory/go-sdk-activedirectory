package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strconv"
)

var (
	ErrReplicationReferenceLimit   = errors.New("replication reference read limit exceeded")
	ErrReplicationReferenceChanged = errors.New("replication reference source changed during retrieval")
)

// ReplicationTransport selects the interSiteTransport container. IP is the
// default. AD LDS does not support SMTP replication.
type ReplicationTransport string

const (
	ReplicationTransportIP   ReplicationTransport = "IP"
	ReplicationTransportSMTP ReplicationTransport = "SMTP"
)

type ReplicationSiteLinkOptions uint32

const (
	ReplicationSiteLinkUseNotify ReplicationSiteLinkOptions = 1 << iota
	ReplicationSiteLinkTwoWaySync
	ReplicationSiteLinkDisableCompression
)

type ReplicationConnectionOptions uint32

const (
	ReplicationConnectionGenerated ReplicationConnectionOptions = 1 << iota
	ReplicationConnectionTwoWaySync
	ReplicationConnectionOverrideNotifyDefault
	ReplicationConnectionUseNotify
	ReplicationConnectionDisableCompression
	ReplicationConnectionUserOwnedSchedule
	ReplicationConnectionRODCTopology
	ReplicationConnectionIgnoreSchedule ReplicationConnectionOptions = 0x80000000
)

type ReplicationSiteLink struct {
	Raw                                 Object
	GUID                                *GUID
	Name, Description                   *string
	Transport                           ReplicationTransport
	Cost, ReplicationFrequencyInMinutes *int32
	Options                             *ReplicationSiteLinkOptions
	Schedule                            *ReplicationSchedule
}
type ReplicationSiteLinkBridge struct {
	Raw               Object
	GUID              *GUID
	Name, Description *string
	Transport         ReplicationTransport
}
type ReplicationConnection struct {
	Raw                                          Object
	GUID                                         *GUID
	Name, Description, FromServerDN, TransportDN *string
	DestinationDSADN                             string
	Enabled                                      *bool
	Options                                      *ReplicationConnectionOptions
	Schedule                                     *ReplicationSchedule
}
type ReplicationLinkReadOptions struct {
	ResolveIdentityOptions
	References ReplicationReferenceLimits
}
type ReplicationSiteLinkResult struct {
	Link        *ReplicationSiteLink
	Observation IdentityResult
	Sites       ReplicationReferencesResult
}
type ReplicationSiteLinkBridgeResult struct {
	Bridge      *ReplicationSiteLinkBridge
	Observation IdentityResult
	SiteLinks   ReplicationReferencesResult
}
type ReplicationConnectionResult struct {
	Connection  *ReplicationConnection
	Observation IdentityResult
}
type ReplicationSiteLinksResult struct {
	Links       []ReplicationSiteLinkResult
	Observation SearchResult
}
type ReplicationSiteLinkBridgesResult struct {
	Bridges     []ReplicationSiteLinkBridgeResult
	Observation SearchResult
}
type ReplicationConnectionsResult struct {
	Connections []ReplicationConnection
	Observation SearchResult
}

func replicationTransportParent(root RootDSE, config Config, partition string, transport ReplicationTransport) (string, error) {
	configuration, err := topologyConfiguration(root, config, partition)
	if err != nil {
		return "", err
	}
	if transport == "" {
		transport = ReplicationTransportIP
	}
	if transport != ReplicationTransportIP && transport != ReplicationTransportSMTP {
		return "", ErrReplicationTopology
	}
	if root.Capabilities().Type == DirectoryADLDS && transport == ReplicationTransportSMTP {
		return "", ErrUnsupported
	}
	return "CN=" + string(transport) + ",CN=Inter-Site Transports,CN=Sites," + configuration, nil
}
func replicationObjectTransport(object Object, configuration string) (ReplicationTransport, error) {
	for _, transport := range []ReplicationTransport{ReplicationTransportIP, ReplicationTransportSMTP} {
		parent := "CN=" + string(transport) + ",CN=Inter-Site Transports,CN=Sites," + configuration
		actual, err := parentDirectoryDN(object.DistinguishedName)
		if err == nil && topologySameDN(actual, parent) {
			return transport, nil
		}
	}
	return "", ErrReplicationTopology
}
func replicationLinkProperties(extra []string, bridge bool) []string {
	attrs := append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "description")
	if !bridge {
		attrs = append(attrs, "cost", "replInterval", "options", "schedule")
	}
	return attrs
}
func replicationConnectionProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "description", "fromServer", "transportType", "enabledConnection", "options", "schedule")
}
func replicationScheduleValue(object Object) (*ReplicationSchedule, error) {
	if _, state := object.Attribute("schedule"); state == AttributeAbsent || state == AttributeUnloaded {
		return nil, nil
	}
	value, err := object.Values("schedule").Single()
	if err != nil {
		return nil, err
	}
	schedule, err := ReplicationScheduleFromBytes(value.Bytes())
	if err != nil {
		return nil, err
	}
	return &schedule, nil
}
func replicationInt32(text string) (int32, error) {
	n, e := strconv.ParseInt(text, 10, 32)
	return int32(n), e
}
func decodeReplicationLink(object Object, configuration string) (ReplicationSiteLink, error) {
	result := ReplicationSiteLink{Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	result.Cost = decodeScalar(&d, "cost", replicationInt32)
	result.ReplicationFrequencyInMinutes = decodeScalar(&d, "replInterval", replicationInt32)
	if flags := decodeScalar(&d, "options", parseDirectoryMask); flags != nil {
		value := ReplicationSiteLinkOptions(*flags)
		result.Options = &value
	}
	guid, e := topologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	transport, te := replicationObjectTransport(object, configuration)
	result.Transport = transport
	schedule, se := replicationScheduleValue(object)
	result.Schedule = schedule
	return result, errors.Join(e, te, se, topologyClass(object, "siteLink"), errors.Join(d.errors...))
}
func decodeReplicationBridge(object Object, configuration string) (ReplicationSiteLinkBridge, error) {
	result := ReplicationSiteLinkBridge{Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	guid, e := topologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	result.Transport, e = replicationTransportJoin(object, configuration, e)
	return result, errors.Join(e, topologyClass(object, "siteLinkBridge"), errors.Join(d.errors...))
}
func replicationTransportJoin(object Object, configuration string, err error) (ReplicationTransport, error) {
	t, e := replicationObjectTransport(object, configuration)
	return t, errors.Join(err, e)
}
func (c *Client) readReplicationLink(ctx context.Context, identity Identity, options ReplicationLinkReadOptions, bridge bool) (IdentityResult, ReplicationReferencesResult, error) {
	var observed IdentityResult
	var refs ReplicationReferencesResult
	limits, err := normalizeReplicationReferenceLimits(options.References)
	if err != nil {
		return observed, refs, err
	}
	if err := topologyIdentity(identity, options.ResolveIdentityOptions); err != nil {
		return observed, refs, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = replicationLinkProperties(resolve.Properties, bridge)
		observed, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if err != nil {
			return err
		}
		class, attr := "siteLink", "siteList"
		if bridge {
			class, attr = "siteLinkBridge", "siteLinkList"
		}
		transport, err := replicationObjectTransport(*observed.Object, configuration)
		if err != nil {
			return err
		}
		parent, err := replicationTransportParent(root, c.config, configuration, transport)
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return err
		}
		refs, err = collectReplicationReferences(ctx, c.session, *observed.Object, attr, limits)
		return err
	})
	return observed, refs, err
}
func (c *Client) ReplicationSiteLink(ctx context.Context, identity Identity, options ReplicationLinkReadOptions) (ReplicationSiteLinkResult, error) {
	var result ReplicationSiteLinkResult
	var err error
	result.Observation, result.Sites, err = c.readReplicationLink(ctx, identity, options, false)
	if result.Observation.Object != nil {
		value, e := decodeReplicationLink(*result.Observation.Object, result.Observation.Partition)
		result.Link = &value
		err = errors.Join(err, e)
	}
	return result, err
}
func (c *Client) ReplicationSiteLinkBridge(ctx context.Context, identity Identity, options ReplicationLinkReadOptions) (ReplicationSiteLinkBridgeResult, error) {
	var result ReplicationSiteLinkBridgeResult
	var err error
	result.Observation, result.SiteLinks, err = c.readReplicationLink(ctx, identity, options, true)
	if result.Observation.Object != nil {
		value, e := decodeReplicationBridge(*result.Observation.Object, result.Observation.Partition)
		result.Bridge = &value
		err = errors.Join(err, e)
	}
	return result, err
}

// Searches retain each row and its bounded reference observations on failure.
func (c *Client) searchReplicationLinks(ctx context.Context, transport ReplicationTransport, options SearchOptions, limits ReplicationReferenceLimits, bridge bool) (SearchResult, []ReplicationReferencesResult, string, error) {
	var result SearchResult
	var refs []ReplicationReferencesResult
	var configuration string
	limits, err := normalizeReplicationReferenceLimits(limits)
	if err != nil {
		return result, refs, configuration, err
	}
	if err := options.Validate(); err != nil {
		return result, refs, configuration, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err = topologyConfiguration(root, c.config, "")
		if err != nil {
			return err
		}
		parent, err := replicationTransportParent(root, c.config, configuration, transport)
		if err != nil {
			return err
		}
		class, attr := "siteLink", "siteList"
		if bridge {
			class, attr = "siteLinkBridge", "siteLinkList"
		}
		query, err := topologySearch(options, parent, class)
		if err != nil {
			return err
		}
		query.Properties = replicationLinkProperties(options.Properties, bridge)
		result, err = searchIdentitySession(ctx, c.session, query)
		for _, object := range result.Objects {
			var values ReplicationReferencesResult
			e := topologyDirectChild(object, parent, class)
			if e == nil {
				values, e = collectReplicationReferences(ctx, c.session, object, attr, limits)
			}
			refs = append(refs, values)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Complete = false
	}
	return result, refs, configuration, err
}
func (c *Client) ReplicationSiteLinks(ctx context.Context, transport ReplicationTransport, options SearchOptions, limits ReplicationReferenceLimits) (ReplicationSiteLinksResult, error) {
	var result ReplicationSiteLinksResult
	observed, refs, configuration, err := c.searchReplicationLinks(ctx, transport, options, limits, false)
	result.Observation = observed
	for i, object := range observed.Objects {
		link, e := decodeReplicationLink(object, configuration)
		err = errors.Join(err, e)
		result.Links = append(result.Links, ReplicationSiteLinkResult{Link: &link, Observation: IdentityResult{Object: &object, Partition: configuration, Complete: true}, Sites: refs[i]})
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
func (c *Client) ReplicationSiteLinkBridges(ctx context.Context, transport ReplicationTransport, options SearchOptions, limits ReplicationReferenceLimits) (ReplicationSiteLinkBridgesResult, error) {
	var result ReplicationSiteLinkBridgesResult
	observed, refs, configuration, err := c.searchReplicationLinks(ctx, transport, options, limits, true)
	result.Observation = observed
	for i, object := range observed.Objects {
		bridge, e := decodeReplicationBridge(object, configuration)
		err = errors.Join(err, e)
		result.Bridges = append(result.Bridges, ReplicationSiteLinkBridgeResult{Bridge: &bridge, Observation: IdentityResult{Object: &object, Partition: configuration, Complete: true}, SiteLinks: refs[i]})
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
