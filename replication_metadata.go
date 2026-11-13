package activedirectory

// ReplicationAttributeMetadataQuery reads the last replication stamp for each
// selected attribute. ObjectDN is an exact DN, including a tombstone DN when
// IncludeDeletedObjects is set. Properties contains exact LDAP display names;
// empty or ["*"] selects all. Attribute values themselves are not requested.
type ReplicationAttributeMetadataQuery struct {
	Selection  ReplicationSelection
	ObjectDN   string
	Properties []string
	// IncludeLinkedValues additionally reads individual link-value stamps.
	IncludeLinkedValues bool
	// IncludeDeletedObjects requests the critical show-deleted control.
	IncludeDeletedObjects bool
	// IncludeDeactivatedLinks also exposes links to deleted objects. Requires
	// IncludeLinkedValues; stored deleted-object links require both controls.
	IncludeDeactivatedLinks bool
}

// ReplicationVectorQuery reads each specified NC root. Empty PartitionDNs reads
// every naming context advertised by each server's RootDSE. An explicit list
// retains a result and error for each missing or unreadable partition.
type ReplicationVectorQuery struct {
	Selection    ReplicationSelection
	PartitionDNs []string
}

// ReplicationAttributeMetadata is a current replication stamp, not a change
// log. OriginatingServerDN is the reported nTDSDSA DN (nil if not reported),
// never a guessed DNS host. Nonlinked multivalued attributes have one stamp.
type ReplicationAttributeMetadata struct {
	AttributeName           string
	Version                 uint32
	LastOriginatingChange   ReplicationTimestamp
	OriginatingInvocationID string
	OriginatingUSN          int64
	LocalUSN                int64
	OriginatingServerDN     *string
}

// ReplicationLinkedValueMetadata preserves per-value stamps separately from
// whole-attribute stamps. ValueDN is the server's object-DN field; Data retains
// the additional raw value bytes. Deleted.Ticks == 0 means a present link;
// a nonzero value records a deleted link retained by directory policy.
type ReplicationLinkedValueMetadata struct {
	ReplicationAttributeMetadata
	ValueDN *string
	Data    []byte
	Created ReplicationTimestamp
	Deleted ReplicationTimestamp
}

// ReplicationCursor is one source invocation's up-to-dateness watermark in a
// partition. HighestUSN is the native usnAttributeFilter, not a server-local USN.
type ReplicationCursor struct {
	InvocationID   string
	HighestUSN     int64
	LastSuccess    ReplicationTimestamp
	SourceServerDN *string
}

type ReplicationAttributeMetadataServer struct {
	Observation       ReplicationServerObservation
	ObjectDN          string
	AttributesState   ReplicationQueryState
	LinkedValuesState ReplicationQueryState
	Attributes        []ReplicationAttributeMetadata
	LinkedValues      []ReplicationLinkedValueMetadata
	// Objects retains every raw LDAP response and its ranged description.
	Objects []Object
}

type ReplicationVectorPartition struct {
	PartitionDN string
	State       ReplicationQueryState
	Cursors     []ReplicationCursor
	Objects     []Object
}

type ReplicationVectorServer struct {
	Observation ReplicationServerObservation
	Partitions  []ReplicationVectorPartition
}

type ReplicationAttributeMetadataResult struct {
	Targets  ReplicationTargets
	Servers  []ReplicationAttributeMetadataServer
	Complete bool
}

type ReplicationVectorsResult struct {
	Targets  ReplicationTargets
	Servers  []ReplicationVectorServer
	Complete bool
}
