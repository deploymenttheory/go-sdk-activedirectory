package model

import (
	"errors"
	"slices"
	"strconv"
)

var (
	ErrReplicationReferenceLimit   = errors.New("replication reference read limit exceeded")
	ErrReplicationReferenceChanged = errors.New(
		"replication reference source changed during retrieval",
	)
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

func InternalReplicationTransportParent(
	root RootDSE,
	config Config,
	partition string,
	transport ReplicationTransport,
) (string, error) {
	configuration, err := InternalTopologyConfiguration(root, config, partition)
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
		return "", root.Capabilities().RequireADDS("SMTPReplicationTransport")
	}
	return "CN=" + string(transport) + ",CN=Inter-Site Transports,CN=Sites," + configuration, nil
}

func InternalReplicationObjectTransport(
	object Object,
	configuration string,
) (ReplicationTransport, error) {
	for _, transport := range []ReplicationTransport{ReplicationTransportIP, ReplicationTransportSMTP} {
		parent := "CN=" + string(transport) + ",CN=Inter-Site Transports,CN=Sites," + configuration
		actual, err := InternalParentDirectoryDN(object.DistinguishedName)
		if err == nil && InternalTopologySameDN(actual, parent) {
			return transport, nil
		}
	}
	return "", ErrReplicationTopology
}

func InternalReplicationLinkProperties(extra []string, bridge bool) []string {
	attrs := append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"description",
	)
	if !bridge {
		attrs = append(attrs, "cost", "replInterval", "options", "schedule")
	}
	return attrs
}

func InternalReplicationConnectionProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"description",
		"fromServer",
		"transportType",
		"enabledConnection",
		"options",
		"schedule",
	)
}

func InternalReplicationScheduleValue(object Object) (*ReplicationSchedule, error) {
	if _, state := object.Attribute(
		"schedule",
	); state == AttributeAbsent ||
		state == AttributeUnloaded {
		return nil, nil //nolint:nilnil // No schedule is a valid projection; the raw object retains absence/unloaded state.
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

func InternalReplicationInt32(text string) (int32, error) {
	n, e := strconv.ParseInt(text, 10, 32)
	return int32(n), e
}

func InternalDecodeReplicationLink(
	object Object,
	configuration string,
) (ReplicationSiteLink, error) {
	result := ReplicationSiteLink{Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	result.Cost = InternalDecodeScalar(&d, "cost", InternalReplicationInt32)
	result.ReplicationFrequencyInMinutes = InternalDecodeScalar(
		&d,
		"replInterval",
		InternalReplicationInt32,
	)
	if flags := InternalDecodeScalar(&d, "options", InternalParseDirectoryMask); flags != nil {
		value := ReplicationSiteLinkOptions(*flags)
		result.Options = &value
	}
	guid, e := InternalTopologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	transport, te := InternalReplicationObjectTransport(object, configuration)
	result.Transport = transport
	schedule, se := InternalReplicationScheduleValue(object)
	result.Schedule = schedule
	return result, errors.Join(
		e,
		te,
		se,
		InternalTopologyClass(object, "siteLink"),
		errors.Join(d.InternalErrors...),
	)
}

func InternalDecodeReplicationBridge(
	object Object,
	configuration string,
) (ReplicationSiteLinkBridge, error) {
	result := ReplicationSiteLinkBridge{Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	guid, e := InternalTopologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	result.Transport, e = InternalReplicationTransportJoin(object, configuration, e)
	return result, errors.Join(
		e,
		InternalTopologyClass(object, "siteLinkBridge"),
		errors.Join(d.InternalErrors...),
	)
}

func InternalReplicationTransportJoin(
	object Object,
	configuration string,
	err error,
) (ReplicationTransport, error) {
	t, e := InternalReplicationObjectTransport(object, configuration)
	return t, errors.Join(err, e)
}
