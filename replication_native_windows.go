//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
)

type replicationAPI struct {
	find            func(*win32.Proc) error
	bind            func(*string, *string, *win32.GUID, *string, unsafe.Pointer, *string, uint32, *foundation.HANDLE) uint32
	unBind          func(*foundation.HANDLE) uint32
	setTimeout      func(foundation.HANDLE, uint32) uint32
	credentials     func(*Credentials) (unsafe.Pointer, error)
	freeCredentials func(unsafe.Pointer)
	getInfo         func(foundation.HANDLE, nativead.DS_REPL_INFO_TYPE, *string, *win32.GUID, *string, *string, uint32, uint32, *unsafe.Pointer) uint32
	freeInfo        func(nativead.DS_REPL_INFO_TYPE, unsafe.Pointer)
}

func readReplicationNative(ctx context.Context, config Config, root RootDSE, instance []byte, request replicationRequest) (map[replicationInfo]replicationNativeReply, error) {
	return readReplicationWithAPI(ctx, config, root, instance, request, replicationAPI{
		find: func(proc *win32.Proc) error { return proc.Find() }, bind: nativead.DsBindByInstance, unBind: nativead.DsUnBind, setTimeout: nativead.DsBindingSetTimeout,
		credentials: makeReplicationCredentials, freeCredentials: nativead.DsFreePasswordCredentials,
		getInfo: nativead.DsReplicaGetInfo2W, freeInfo: nativead.DsReplicaFreeInfo,
	})
}

func makeReplicationCredentials(credentials *Credentials) (unsafe.Pointer, error) {
	if credentials == nil {
		return nil, nil
	}
	// Requires the upstream mutable UTF-16 credential input companion; the
	// generated *string wrapper cannot meet the SDK's password-erasure contract.
	return nil, fmt.Errorf("%w: mutable native replication credentials unavailable", ErrUnsupported)
}

func readReplicationWithAPI(ctx context.Context, config Config, root RootDSE, instance []byte, request replicationRequest, api replicationAPI) (result map[replicationInfo]replicationNativeReply, err error) {
	result = make(map[replicationInfo]replicationNativeReply)
	config, err = config.normalized()
	if err != nil {
		return result, err
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	if config.Authentication != AuthenticationNegotiate {
		return result, ErrInvalidConfig
	}
	for _, proc := range []*win32.Proc{nativead.Procs.DsBindByInstance, nativead.Procs.DsUnBind, nativead.Procs.DsBindingSetTimeout, nativead.Procs.DsReplicaGetInfo2W, nativead.Procs.DsReplicaFreeInfo} {
		if err = api.find(proc); err != nil {
			return result, errors.Join(ErrUnsupported, err)
		}
	}
	var guid *win32.GUID
	switch root.Capabilities().Type {
	case DirectoryADDS:
	case DirectoryADLDS:
		if len(instance) != 16 {
			return result, ErrInvalidResult
		}
		guid = &win32.GUID{Data1: binary.LittleEndian.Uint32(instance), Data2: binary.LittleEndian.Uint16(instance[4:]), Data3: binary.LittleEndian.Uint16(instance[6:])}
		copy(guid.Data4[:], instance[8:])
	default:
		return result, ErrUnsupportedDirectory
	}
	// Keep the caller's security identity through binding, synchronous queries,
	// unbinding and credential release. No background cancellation goroutine can
	// outlive either native owner.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	credential, err := api.credentials(config.Credentials)
	if credential != nil {
		defer api.freeCredentials(credential)
	}
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, context.Cause(ctx)) }()
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var handle foundation.HANDLE
	status := api.bind(&config.Endpoint.Host, nil, guid, nil, credential, nil, 0, &handle)
	defer func() {
		if handle != 0 {
			err = errors.Join(err, nativeStatus("DsUnBindW", api.unBind(&handle)))
		}
	}()
	if status != 0 {
		return result, nativeStatus("DsBindByInstanceW", status)
	}
	if handle == 0 {
		return result, ErrInvalidNativeResult
	}
	for _, kind := range request.kinds {
		wait, waitErr := remainingWait(ctx, config.Timeout)
		if waitErr != nil {
			result[kind] = replicationNativeReply{err: waitErr}
			continue
		}
		seconds := uint32((wait + time.Second - 1) / time.Second)
		if timeoutErr := nativeStatus("DsBindingSetTimeout", api.setTimeout(handle, seconds)); timeoutErr != nil {
			result[kind] = replicationNativeReply{err: timeoutErr}
			continue
		}
		var partition *string
		if kind == replicationNeighbors && request.partition != "" {
			partition = &request.partition
		}
		data, queryErr := queryReplicationInfo(ctx, api, handle, nativead.DS_REPL_INFO_TYPE(kind), partition)
		result[kind] = replicationNativeReply{data: data, err: queryErr}
	}
	return result, nil
}

func queryReplicationInfo(ctx context.Context, api replicationAPI, handle foundation.HANDLE, kind nativead.DS_REPL_INFO_TYPE, partition *string) (result replicationNativeData, err error) {
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var owner unsafe.Pointer
	status := api.getInfo(handle, kind, partition, nil, nil, nil, 0, 0, &owner)
	defer func() {
		if owner != nil {
			api.freeInfo(kind, owner)
		}
		err = errors.Join(err, context.Cause(ctx))
	}()
	if status != 0 {
		return result, nativeStatus("DsReplicaGetInfo2W", status)
	}
	if owner == nil {
		return result, fmt.Errorf("%w: DsReplicaGetInfo2W returned NULL", ErrInvalidNativeResult)
	}
	switch kind {
	case nativead.DS_REPL_INFO_NEIGHBORS:
		container := (*nativead.DS_REPL_NEIGHBORSW)(owner)
		if container.CNumNeighbors > maxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		for _, raw := range unsafe.Slice(&container.RgNeighbor[0], int(container.CNumNeighbors)) {
			partner, decodeErr := decodeReplicationNeighbor(raw)
			result.partners = append(result.partners, partner)
			err = errors.Join(err, decodeErr)
		}
	case nativead.DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES, nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES:
		container := (*nativead.DS_REPL_KCC_DSA_FAILURESW)(owner)
		if container.CNumEntries > maxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		for _, raw := range unsafe.Slice(&container.RgDsaFailure[0], int(container.CNumEntries)) {
			name, decodeErr := copyDiscoveryText(raw.PszDsaDN)
			failure := ReplicationFailure{PartnerDN: name, PartnerGUID: raw.UuidDsaObjGuid.String(), Time: replicationFiletime(raw.FtimeFirstFailure), FailureCount: raw.CNumFailures, LastResult: raw.DwLastResult, LastResultAvailable: raw.DwLastResult != 0}
			if kind == nativead.DS_REPL_INFO_KCC_DSA_LINK_FAILURES {
				failure.Kind = ReplicationLinkFailure
			}
			result.failures = append(result.failures, failure)
			err = errors.Join(err, decodeErr)
		}
	case nativead.DS_REPL_INFO_PENDING_OPS:
		container := (*nativead.DS_REPL_PENDING_OPSW)(owner)
		if container.CNumPendingOps > maxReplicationRecords {
			return result, ErrInvalidNativeResult
		}
		result.started = replicationFiletime(container.FtimeCurrentOpStarted)
		for _, raw := range unsafe.Slice(&container.RgPendingOp[0], int(container.CNumPendingOps)) {
			operation, decodeErr := decodeReplicationOperation(raw)
			result.operations = append(result.operations, operation)
			err = errors.Join(err, decodeErr)
		}
	default:
		err = ErrInvalidReplicationQuery
	}
	return result, err
}

// Native owns the flexible arrays. The sanity limit rejects a corrupt count;
// it never silently truncates an otherwise successful result.
const maxReplicationRecords = 1 << 20

func replicationFiletime(value foundation.FILETIME) ReplicationTimestamp {
	return replicationTicks(uint64(value.DwHighDateTime)<<32 | uint64(value.DwLowDateTime))
}

func replicationValue[T any](v T) *T { return &v }

func decodeReplicationNeighbor(raw nativead.DS_REPL_NEIGHBORW) (ReplicationPartner, error) {
	result := ReplicationPartner{Direction: ReplicationInbound, ReplicaFlags: replicationValue(raw.DwReplicaFlags), PartitionGUID: replicationValue(raw.UuidNamingContextObjGuid.String()), PartnerGUID: replicationValue(raw.UuidSourceDsaObjGuid.String()), InvocationID: replicationValue(raw.UuidSourceDsaInvocationID.String()), TransportGUID: replicationValue(raw.UuidAsyncIntersiteTransportObjGuid.String()), LastObjectUSN: replicationValue(raw.UsnLastObjChangeSynced), AttributeFilterUSN: replicationValue(raw.UsnAttributeFilter), LastSuccess: replicationFiletime(raw.FtimeLastSyncSuccess), LastAttempt: replicationFiletime(raw.FtimeLastSyncAttempt), LastResult: replicationValue(raw.DwLastSyncResult), ConsecutiveFailures: replicationValue(raw.CNumConsecutiveSyncFailures)}
	var failures []error
	for _, field := range []struct {
		source *uint16
		target **string
	}{{raw.PszNamingContext, &result.PartitionDN}, {raw.PszSourceDsaDN, &result.PartnerDN}, {raw.PszSourceDsaAddress, &result.PartnerAddress}, {raw.PszAsyncIntersiteTransportDN, &result.TransportDN}} {
		var err error
		*field.target, err = copyDiscoveryText(field.source)
		failures = append(failures, err)
	}
	return result, errors.Join(failures...)
}

func decodeReplicationOperation(raw nativead.DS_REPL_OPW) (ReplicationQueueOperation, error) {
	result := ReplicationQueueOperation{Enqueued: replicationFiletime(raw.FtimeEnqueued), SerialNumber: raw.UlSerialNumber, Priority: raw.UlPriority, Type: ReplicationOperationType(raw.OpType), Options: raw.UlOptions, PartitionGUID: raw.UuidNamingContextObjGuid.String(), PartnerGUID: raw.UuidDsaObjGuid.String()}
	var failures []error
	for _, field := range []struct {
		source *uint16
		target **string
	}{{raw.PszNamingContext, &result.PartitionDN}, {raw.PszDsaDN, &result.PartnerDN}, {raw.PszDsaAddress, &result.PartnerAddress}} {
		var err error
		*field.target, err = copyDiscoveryText(field.source)
		failures = append(failures, err)
	}
	return result, errors.Join(failures...)
}
