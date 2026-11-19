// Package drsrwire decodes only the diagnostic NDR32 reply arms needed by the SDK.
// It is an isolated qualification adapter, not an authenticated DRS implementation.
package drsrwire

import "errors"

var (
	ErrMalformedNDR = errors.New("malformed DRS diagnostic NDR32")
	ErrNDRLimit     = errors.New("DRS diagnostic NDR32 exceeds limit")
)

type Reply struct {
	Kind, Status, Count uint32
	Present             bool
	Started             uint64
	Neighbors           []Neighbor
	Failures            []Failure
	Operations          []Operation
}

type Neighbor struct {
	PartitionDN, PartnerDN, PartnerAddress, TransportDN     *string
	PartitionGUID, PartnerGUID, InvocationID, TransportGUID [16]byte
	ReplicaFlags                                            uint32
	LastObjectUSN, AttributeFilterUSN                       int64
	LastSuccess, LastAttempt                                uint64
	LastResult, ConsecutiveFailures                         uint32
}

type Failure struct {
	PartnerDN                *string
	PartnerGUID              [16]byte
	Time                     uint64
	FailureCount, LastResult uint32
}

type Operation struct {
	PartitionDN, PartnerDN, PartnerAddress *string
	PartitionGUID, PartnerGUID             [16]byte
	Enqueued                               uint64
	SerialNumber, Priority, Type, Options  uint32
}
