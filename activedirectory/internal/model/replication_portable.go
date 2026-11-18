package model

import (
	"context"
	"errors"
)

const internalPortableReplicationRecordLimit = 1 << 20

// InternalPortableReplicationReply is the transport-owned observation boundary,
// after authenticated RPC framing and bounded wire decoding. Present records
// the actual output-container pointer. Count is the server's declared count.
// This type and its projection do not implement or qualify the RPC transport.
type InternalPortableReplicationReply struct {
	Kind       InternalReplicationInfo
	Status     uint32
	Present    bool
	Count      uint32
	Started    uint64
	Neighbors  []InternalPortableReplicationNeighbor
	Failures   []InternalPortableReplicationFailure
	Operations []InternalPortableReplicationOperation
}

type InternalPortableReplicationNeighbor struct {
	PartitionDN, PartnerDN, PartnerAddress, TransportDN     *string
	PartitionGUID, PartnerGUID, InvocationID, TransportGUID [16]byte
	ReplicaFlags                                            uint32
	LastObjectUSN, AttributeFilterUSN                       int64
	LastSuccess, LastAttempt                                uint64
	LastResult, ConsecutiveFailures                         uint32
}

type InternalPortableReplicationFailure struct {
	PartnerDN                *string
	PartnerGUID              [16]byte
	Time                     uint64
	FailureCount, LastResult uint32
}

type InternalPortableReplicationOperation struct {
	PartitionDN, PartnerDN, PartnerAddress *string
	PartitionGUID, PartnerGUID             [16]byte
	Enqueued                               uint64
	SerialNumber, Priority, Type, Options  uint32
}

// InternalDecodePortableReplicationObservation copies validated transport
// observations into the existing native-equivalent result. It preserves valid
// prefixes on incomplete arrays and never treats missing containers as empty.
// Wire authentication, NDR parsing and RPC fault validation remain prerequisites.
func InternalDecodePortableReplicationObservation(
	ctx context.Context,
	requested InternalReplicationInfo,
	raw InternalPortableReplicationReply,
) (reply InternalReplicationNativeReply) {
	if !internalPortableReplicationKind(requested) {
		reply.InternalErr = ErrInvalidReplicationQuery
		return reply
	}
	if raw.Status != 0 {
		// Like the native API, a nonzero operation status does not establish
		// successful output data. Preserve the actual Win32/DRS value exactly.
		reply.InternalErr = errors.Join(&NativeStatusError{Operation: "IDL_DRSGetReplInfo", Code: raw.Status}, context.Cause(ctx))
		return reply
	}
	if raw.Kind != requested || !raw.Present || raw.Count > internalPortableReplicationRecordLimit || !internalPortableReplicationUnion(raw) {
		reply.InternalErr = ErrInvalidResult
		return reply
	}
	available := len(raw.Neighbors) + len(raw.Failures) + len(raw.Operations)
	if int(raw.Count) != available {
		reply.InternalErr = ErrInvalidResult
	}
	count := min(int(raw.Count), available)
	if requested == InternalReplicationPendingOperations {
		reply.InternalData.InternalStarted = InternalReplicationTicks(raw.Started)
	}
	for index := range count {
		if cause := context.Cause(ctx); cause != nil {
			reply.InternalErr = errors.Join(reply.InternalErr, cause)
			return reply
		}
		var err error
		switch requested {
		case InternalReplicationNeighbors:
			var partner ReplicationPartner
			partner, err = internalPortableReplicationNeighbor(raw.Neighbors[index])
			reply.InternalData.InternalPartners = append(reply.InternalData.InternalPartners, partner)
		case InternalReplicationConnectFailures, InternalReplicationLinkFailures:
			var failure ReplicationFailure
			failure, err = internalPortableReplicationFailure(requested, raw.Failures[index])
			reply.InternalData.InternalFailures = append(reply.InternalData.InternalFailures, failure)
		case InternalReplicationPendingOperations:
			var operation ReplicationQueueOperation
			operation, err = internalPortableReplicationOperation(raw.Operations[index])
			reply.InternalData.InternalOperations = append(reply.InternalData.InternalOperations, operation)
		}
		reply.InternalErr = errors.Join(reply.InternalErr, err)
	}
	reply.InternalErr = errors.Join(reply.InternalErr, context.Cause(ctx))
	return reply
}

func internalPortableReplicationKind(kind InternalReplicationInfo) bool {
	return kind == InternalReplicationNeighbors || kind == InternalReplicationConnectFailures ||
		kind == InternalReplicationLinkFailures || kind == InternalReplicationPendingOperations
}

func internalPortableReplicationUnion(raw InternalPortableReplicationReply) bool {
	switch raw.Kind {
	case InternalReplicationNeighbors:
		return len(raw.Failures) == 0 && len(raw.Operations) == 0
	case InternalReplicationConnectFailures, InternalReplicationLinkFailures:
		return len(raw.Neighbors) == 0 && len(raw.Operations) == 0
	case InternalReplicationPendingOperations:
		return len(raw.Neighbors) == 0 && len(raw.Failures) == 0
	}
	return false
}
