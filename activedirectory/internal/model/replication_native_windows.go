//go:build windows && (amd64 || arm64)

package model

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
)

type InternalReplicationAPI struct {
	InternalFind            func(*win32.Proc) error
	InternalBind            func(*string, *string, *win32.GUID, *string, unsafe.Pointer, *string, uint32, *foundation.HANDLE) uint32
	InternalUnBind          func(*foundation.HANDLE) uint32
	InternalSetTimeout      func(foundation.HANDLE, uint32) uint32
	InternalCredentials     func(*Credentials) (unsafe.Pointer, error)
	InternalFreeCredentials func(unsafe.Pointer)
	InternalGetInfo         func(foundation.HANDLE, nativead.DS_REPL_INFO_TYPE, *string, *win32.GUID, *string, *string, uint32, uint32, *unsafe.Pointer) uint32
	InternalFreeInfo        func(nativead.DS_REPL_INFO_TYPE, unsafe.Pointer)
}

func InternalQueryReplicationInfo(
	ctx context.Context,
	api InternalReplicationAPI,
	handle foundation.HANDLE,
	kind nativead.DS_REPL_INFO_TYPE,
	partition *string,
) (result InternalReplicationNativeData, err error) {
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var owner unsafe.Pointer
	status := api.InternalGetInfo(handle, kind, partition, nil, nil, nil, 0, 0, &owner)
	defer func() {
		if owner != nil {
			api.InternalFreeInfo(kind, owner)
		}
		err = errors.Join(err, context.Cause(ctx))
	}()
	if status != 0 {
		return result, InternalNativeStatus("DsReplicaGetInfo2W", status)
	}
	if owner == nil {
		return result, fmt.Errorf("%w: DsReplicaGetInfo2W returned NULL", ErrInvalidNativeResult)
	}
	switch kind {
	case nativead.DS_REPL_INFO_NEIGHBORS:
		container := (*nativead.DS_REPL_NEIGHBORSW)(owner)
		if container.CNumNeighbors > InternalMaxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		for _, raw := range unsafe.Slice(&container.RgNeighbor[0], int(container.CNumNeighbors)) {
			partner, decodeErr := InternalDecodeReplicationNeighbor(raw)
			result.InternalPartners = append(result.InternalPartners, partner)
			err = errors.Join(err, decodeErr)
		}
	case nativead.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES,
		nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES:
		container := (*nativead.DS_REPL_KCC_DSA_FAILURESW)(owner)
		if container.CNumEntries > InternalMaxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		for _, raw := range unsafe.Slice(&container.RgDsaFailure[0], int(container.CNumEntries)) {
			name, decodeErr := InternalCopyDiscoveryText(raw.PszDsaDN)
			failure := ReplicationFailure{
				PartnerDN:           name,
				PartnerGUID:         raw.UuidDsaObjGuid.String(),
				Time:                InternalReplicationFiletime(raw.FtimeFirstFailure),
				FailureCount:        raw.CNumFailures,
				LastResult:          raw.DwLastResult,
				LastResultAvailable: raw.DwLastResult != 0,
			}
			if kind == nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES {
				failure.Kind = ReplicationLinkFailure
			}
			result.InternalFailures = append(result.InternalFailures, failure)
			err = errors.Join(err, decodeErr)
		}
	case nativead.DS_REPL_INFO_PENDING_OPS:
		container := (*nativead.DS_REPL_PENDING_OPSW)(owner)
		if container.CNumPendingOps > InternalMaxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		result.InternalStarted = InternalReplicationFiletime(container.FtimeCurrentOpStarted)
		for _, raw := range unsafe.Slice(&container.RgPendingOp[0], int(container.CNumPendingOps)) {
			operation, decodeErr := InternalDecodeReplicationOperation(raw)
			result.InternalOperations = append(result.InternalOperations, operation)
			err = errors.Join(err, decodeErr)
		}
	default:
		err = ErrInvalidReplicationQuery
	}
	return result, err
}

// Native owns the flexible arrays. The sanity limit rejects a corrupt count;
// it never silently truncates an otherwise successful result.
const InternalMaxReplicationRecords = 1 << 20

func InternalReplicationFiletime(value foundation.FILETIME) ReplicationTimestamp {
	return InternalReplicationTicks(uint64(value.DwHighDateTime)<<32 | uint64(value.DwLowDateTime))
}

func InternalReplicationValue[T any](v T) *T { return &v }

func InternalDecodeReplicationNeighbor(raw nativead.DS_REPL_NEIGHBORW) (ReplicationPartner, error) {
	result := ReplicationPartner{
		Direction:     ReplicationInbound,
		ReplicaFlags:  InternalReplicationValue(raw.DwReplicaFlags),
		PartitionGUID: InternalReplicationValue(raw.UuidNamingContextObjGuid.String()),
		PartnerGUID:   InternalReplicationValue(raw.UuidSourceDsaObjGuid.String()),
		InvocationID:  InternalReplicationValue(raw.UuidSourceDsaInvocationID.String()),
		TransportGUID: InternalReplicationValue(
			raw.UuidAsyncIntersiteTransportObjGuid.String(),
		),
		LastObjectUSN:       InternalReplicationValue(raw.UsnLastObjChangeSynced),
		AttributeFilterUSN:  InternalReplicationValue(raw.UsnAttributeFilter),
		LastSuccess:         InternalReplicationFiletime(raw.FtimeLastSyncSuccess),
		LastAttempt:         InternalReplicationFiletime(raw.FtimeLastSyncAttempt),
		LastResult:          InternalReplicationValue(raw.DwLastSyncResult),
		ConsecutiveFailures: InternalReplicationValue(raw.CNumConsecutiveSyncFailures),
	}
	var failures []error
	for _, field := range []struct {
		InternalSource *uint16
		InternalTarget **string
	}{
		{raw.PszNamingContext, &result.PartitionDN},
		{raw.PszSourceDsaDN, &result.PartnerDN},
		{raw.PszSourceDsaAddress, &result.PartnerAddress},
		{raw.PszAsyncIntersiteTransportDN, &result.TransportDN},
	} {
		var err error
		*field.InternalTarget, err = InternalCopyDiscoveryText(field.InternalSource)
		failures = append(failures, err)
	}
	return result, errors.Join(failures...)
}

func InternalDecodeReplicationOperation(
	raw nativead.DS_REPL_OPW,
) (ReplicationQueueOperation, error) {
	result := ReplicationQueueOperation{
		Enqueued:      InternalReplicationFiletime(raw.FtimeEnqueued),
		SerialNumber:  raw.UlSerialNumber,
		Priority:      raw.UlPriority,
		Type:          ReplicationOperationType(raw.OpType),
		Options:       raw.UlOptions,
		PartitionGUID: raw.UuidNamingContextObjGuid.String(),
		PartnerGUID:   raw.UuidDsaObjGuid.String(),
	}
	var failures []error
	for _, field := range []struct {
		InternalSource *uint16
		InternalTarget **string
	}{{raw.PszNamingContext, &result.PartitionDN}, {raw.PszDsaDN, &result.PartnerDN}, {raw.PszDsaAddress, &result.PartnerAddress}} {
		var err error
		*field.InternalTarget, err = InternalCopyDiscoveryText(field.InternalSource)
		failures = append(failures, err)
	}
	return result, errors.Join(failures...)
}
