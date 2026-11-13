package activedirectory

import (
	"errors"
	"fmt"
	"time"
)

var ErrInvalidReplicationQuery = errors.New("invalid replication diagnostics query")

// ReplicationScope determines which servers are selected before any per-server
// replication query. Domain, forest and site scopes require AD DS topology.
type ReplicationScope uint8

const (
	ReplicationScopeServer ReplicationScope = iota
	ReplicationScopeDomain
	ReplicationScopeForest
	ReplicationScopeSite
)

// ReplicationSelection resolves targets through Config.Endpoint. Server scope
// uses Servers, or the configured endpoint when Servers is empty. DomainDNS and
// ForestDNS select or verify a domain/forest in the anchor's authenticated
// topology. Empty names select that topology's current domain or forest.
// SiteName names a site in that forest. No trust or referral is followed.
type ReplicationSelection struct {
	Scope     ReplicationScope
	Servers   []Endpoint
	DomainDNS string
	ForestDNS string
	SiteName  string
}

// ReplicationTargets retains target discovery independently of server health.
// A partial discovery can still yield servers whose results are useful.
type ReplicationTargets struct {
	Requested   ReplicationSelection
	Servers     []Endpoint
	Observation DirectoryObservation
	Complete    bool
}

type ReplicationDirection uint8

const (
	ReplicationInbound ReplicationDirection = iota
	ReplicationOutbound
	ReplicationBoth
)

type ReplicationPartnerQuery struct {
	Selection ReplicationSelection
	Direction ReplicationDirection
	// PartitionDN selects one NC. Empty requests all hosted NCs.
	PartitionDN string
}

type ReplicationFailureQuery struct{ Selection ReplicationSelection }
type ReplicationQueueQuery struct{ Selection ReplicationSelection }

// ReplicationTimestamp preserves native 100ns FILETIME precision. Nil Ticks
// means the source did not report this field. Reported zero ticks are retained,
// with nil UTC, rather than being presented as a successful event in 1601.
type ReplicationTimestamp struct {
	Ticks *uint64
	UTC   *time.Time
}

// ReplicationPartner preserves reported values, including zero GUIDs, unknown
// flag bits and status codes. Nil fields are unreported, not zero. Outbound
// attempt/success/status describe notification delivery; they must not be
// substituted with an inbound partner's synchronization measurements.
type ReplicationPartner struct {
	Direction           ReplicationDirection
	PartitionDN         *string
	PartnerDN           *string
	PartnerAddress      *string
	TransportDN         *string
	ReplicaFlags        *uint32
	PartitionGUID       *string
	PartnerGUID         *string
	InvocationID        *string
	TransportGUID       *string
	LastObjectUSN       *int64
	AttributeFilterUSN  *int64
	LastSuccess         ReplicationTimestamp
	LastAttempt         ReplicationTimestamp
	LastResult          *uint32
	ConsecutiveFailures *uint32
}

type ReplicationFailureKind uint8

const (
	ReplicationConnectionFailure ReplicationFailureKind = iota
	ReplicationLinkFailure
)

// ReplicationFailure.Time is first failure for a connection failure and last
// successful replication for a link failure. LastResult zero means that the
// specific failure code was unavailable; the record still describes a failure.
type ReplicationFailure struct {
	Kind                ReplicationFailureKind
	PartnerDN           *string
	PartnerGUID         string
	Time                ReplicationTimestamp
	FailureCount        uint32
	LastResult          uint32
	LastResultAvailable bool
}

// ReplicationOperationType retains unknown native operation numbers.
type ReplicationOperationType uint32

const (
	ReplicationOperationSync ReplicationOperationType = iota
	ReplicationOperationAdd
	ReplicationOperationDelete
	ReplicationOperationModify
	ReplicationOperationUpdateReferences
)

type ReplicationQueueOperation struct {
	Enqueued       ReplicationTimestamp
	SerialNumber   uint32
	Priority       uint32
	Type           ReplicationOperationType
	Options        uint32
	PartitionDN    *string
	PartnerDN      *string
	PartnerAddress *string
	PartitionGUID  string
	PartnerGUID    string
}

// ReplicationQueryState distinguishes a successful empty native result from a
// failed query or omitted information. An omitted LDAP attribute is not proof
// that the collection is empty: access checks can hide its values.
type ReplicationQueryState struct {
	Requested bool
	Available bool
	Complete  bool
	Error     error `json:"-"`
}

type ReplicationServerObservation struct {
	Endpoint Endpoint
	RootDSE  RootDSE
	Complete bool
	Error    error `json:"-"`
}

type ReplicationPartnerServer struct {
	Observation ReplicationServerObservation
	Inbound     ReplicationQueryState
	Outbound    ReplicationQueryState
	Partners    []ReplicationPartner
	// OutboundObjects retains the raw LDAP XML and ranged descriptions. The
	// sequential LDAP/RPC observations are not an atomic replication snapshot.
	OutboundObjects []Object
}

type ReplicationFailureServer struct {
	Observation ReplicationServerObservation
	Connections ReplicationQueryState
	Links       ReplicationQueryState
	Failures    []ReplicationFailure
}

type ReplicationQueueServer struct {
	Observation             ReplicationServerObservation
	State                   ReplicationQueryState
	CurrentOperationStarted ReplicationTimestamp
	Operations              []ReplicationQueueOperation
}

type ReplicationPartnersResult struct {
	Targets  ReplicationTargets
	Servers  []ReplicationPartnerServer
	Complete bool
}

type ReplicationFailuresResult struct {
	Targets  ReplicationTargets
	Servers  []ReplicationFailureServer
	Complete bool
}

type ReplicationQueueResult struct {
	Targets  ReplicationTargets
	Servers  []ReplicationQueueServer
	Complete bool
}

// ReplicationReadError retains the affected server and native/context cause.
// Other servers' successful results remain in the returned result.
type ReplicationReadError struct {
	Operation string
	Server    Endpoint
	Cause     error
}

func (e *ReplicationReadError) Error() string {
	return fmt.Sprintf("%s on %s incomplete: %v", e.Operation, e.Server.Host, e.Cause)
}

func (e *ReplicationReadError) Unwrap() []error {
	return []error{ErrIncompleteResult, e.Cause}
}

func replicationTicks(ticks uint64) ReplicationTimestamp {
	result := ReplicationTimestamp{Ticks: &ticks}
	if ticks != 0 {
		utc := time.Unix(int64(ticks/10000000)-11644473600, int64(ticks%10000000)*100).UTC()
		result.UTC = &utc
	}
	return result
}
