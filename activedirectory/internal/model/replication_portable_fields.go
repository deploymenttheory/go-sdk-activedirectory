package model

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

func internalPortableReplicationNeighbor(raw InternalPortableReplicationNeighbor) (ReplicationPartner, error) {
	partner := ReplicationPartner{
		Direction:           ReplicationInbound,
		PartitionGUID:       internalPortableReplicationValue(internalPortableReplicationGUID(raw.PartitionGUID)),
		PartnerGUID:         internalPortableReplicationValue(internalPortableReplicationGUID(raw.PartnerGUID)),
		InvocationID:        internalPortableReplicationValue(internalPortableReplicationGUID(raw.InvocationID)),
		TransportGUID:       internalPortableReplicationValue(internalPortableReplicationGUID(raw.TransportGUID)),
		ReplicaFlags:        internalPortableReplicationValue(raw.ReplicaFlags),
		LastObjectUSN:       internalPortableReplicationValue(raw.LastObjectUSN),
		AttributeFilterUSN:  internalPortableReplicationValue(raw.AttributeFilterUSN),
		LastSuccess:         InternalReplicationTicks(raw.LastSuccess),
		LastAttempt:         InternalReplicationTicks(raw.LastAttempt),
		LastResult:          internalPortableReplicationValue(raw.LastResult),
		ConsecutiveFailures: internalPortableReplicationValue(raw.ConsecutiveFailures),
	}
	var failures error
	for _, field := range []struct {
		source *string
		target **string
	}{
		{raw.PartitionDN, &partner.PartitionDN},
		{raw.PartnerDN, &partner.PartnerDN},
		{raw.PartnerAddress, &partner.PartnerAddress},
		{raw.TransportDN, &partner.TransportDN},
	} {
		if field.source == nil {
			continue
		}
		value, err := internalPortableReplicationText(*field.source)
		*field.target = value
		failures = errors.Join(failures, err)
	}
	return partner, failures
}

func internalPortableReplicationFailure(kind InternalReplicationInfo, raw InternalPortableReplicationFailure) (ReplicationFailure, error) {
	var name *string
	var err error
	if raw.PartnerDN != nil {
		name, err = internalPortableReplicationText(*raw.PartnerDN)
	}
	failure := ReplicationFailure{
		Kind:                ReplicationConnectionFailure,
		PartnerDN:           name,
		PartnerGUID:         internalPortableReplicationGUID(raw.PartnerGUID),
		Time:                InternalReplicationTicks(raw.Time),
		FailureCount:        raw.FailureCount,
		LastResult:          raw.LastResult,
		LastResultAvailable: raw.LastResult != 0,
	}
	if kind == InternalReplicationLinkFailures {
		failure.Kind = ReplicationLinkFailure
	}
	return failure, err
}

func internalPortableReplicationOperation(raw InternalPortableReplicationOperation) (ReplicationQueueOperation, error) {
	operation := ReplicationQueueOperation{
		Enqueued:      InternalReplicationTicks(raw.Enqueued),
		SerialNumber:  raw.SerialNumber,
		Priority:      raw.Priority,
		Type:          ReplicationOperationType(raw.Type),
		Options:       raw.Options,
		PartitionGUID: internalPortableReplicationGUID(raw.PartitionGUID),
		PartnerGUID:   internalPortableReplicationGUID(raw.PartnerGUID),
	}
	var failures error
	for _, field := range []struct {
		source *string
		target **string
	}{
		{raw.PartitionDN, &operation.PartitionDN}, {raw.PartnerDN, &operation.PartnerDN}, {raw.PartnerAddress, &operation.PartnerAddress},
	} {
		if field.source == nil {
			continue
		}
		value, err := internalPortableReplicationText(*field.source)
		*field.target = value
		failures = errors.Join(failures, err)
	}
	return operation, failures
}

func internalPortableReplicationText(value string) (*string, error) {
	if !InternalValidDirectoryText(value) {
		return nil, ErrInvalidResult
	}
	return internalPortableReplicationValue(strings.Clone(value)), nil
}

func internalPortableReplicationValue[T any](value T) *T { return &value }

// DRS GUIDs use Windows/NDR byte order in the first three integer fields.
func internalPortableReplicationGUID(value [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%x",
		binary.LittleEndian.Uint32(value[:4]), binary.LittleEndian.Uint16(value[4:6]),
		binary.LittleEndian.Uint16(value[6:8]), value[8], value[9], value[10:])
}
