//go:build windows && (amd64 || arm64)

package engine

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
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalReadReplicationNative(
	ctx context.Context,
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
	return InternalReadReplicationWithAPI(
		ctx,
		config,
		root,
		instance,
		request,
		admodel.InternalReplicationAPI{
			InternalFind:            func(proc *win32.Proc) error { return proc.Find() },
			InternalBind:            nativead.DsBindByInstance,
			InternalUnBind:          nativead.DsUnBind,
			InternalSetTimeout:      nativead.DsBindingSetTimeout,
			InternalCredentials:     InternalMakeReplicationCredentials,
			InternalFreeCredentials: nativead.DsFreePasswordCredentials,
			InternalGetInfo:         nativead.DsReplicaGetInfo2W,
			InternalFreeInfo:        nativead.DsReplicaFreeInfo,
		},
	)
}

func InternalMakeReplicationCredentials(credentials *admodel.Credentials) (unsafe.Pointer, error) {
	if credentials == nil {
		return nil, nil
	}
	for _, proc := range []*win32.Proc{nativead.Procs.DsMakePasswordCredentials, nativead.Procs.DsFreePasswordCredentials} {
		if err := proc.Find(); err != nil {
			return nil, errors.Join(admodel.ErrUnsupported, err)
		}
	}
	return InternalMakeReplicationCredentialsWithAPI(
		credentials,
		nativead.DsMakePasswordCredentialsUTF16,
	)
}

func InternalMakeReplicationCredentialsWithAPI(
	credentials *admodel.Credentials,
	makeCredential func(foundation.PWSTR, foundation.PWSTR, foundation.PWSTR, *unsafe.Pointer) uint32,
) (unsafe.Pointer, error) {
	if credentials == nil {
		return nil, nil
	}
	if err := admodel.InternalValidateReplicationCredentials(credentials); err != nil {
		return nil, err
	}
	user := InternalCredentialUTF16([]byte(credentials.Username))
	domain := InternalCredentialUTF16([]byte(credentials.Domain))
	password := InternalCredentialUTF16(credentials.Password)
	var domainPointer *uint16
	if credentials.Domain != "" {
		domainPointer = &domain[0]
	}
	var owner unsafe.Pointer
	var pin runtime.Pinner
	pin.Pin(&user[0])
	pin.Pin(&domain[0])
	pin.Pin(&password[0])
	pin.Pin(&owner)
	defer pin.Unpin()
	defer func() {
		clear(user)
		clear(domain)
		clear(password)
		runtime.KeepAlive(user)
		runtime.KeepAlive(domain)
		runtime.KeepAlive(password)
	}()
	status := makeCredential(&user[0], domainPointer, &password[0], &owner)
	if status != 0 {
		return owner, admodel.InternalNativeStatus("DsMakePasswordCredentialsW", status)
	}
	if owner == nil {
		return nil, fmt.Errorf(
			"%w: explicit native credentials returned NULL",
			admodel.ErrInvalidNativeResult,
		)
	}
	// The caller owns this opaque allocation and releases it only after its
	// associated binding is unbound, including on subsequent query failure.
	return owner, nil
}

func InternalReadReplicationWithAPI(
	ctx context.Context,
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
	api admodel.InternalReplicationAPI,
) (result map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, err error) {
	result = make(map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply)
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return result, err
	}
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	if config.Authentication != admodel.AuthenticationNegotiate {
		return result, admodel.ErrInvalidConfig
	}
	if err = admodel.InternalValidateReplicationCredentials(config.Credentials); err != nil {
		return result, err
	}
	for _, proc := range []*win32.Proc{
		nativead.Procs.DsBindByInstance,
		nativead.Procs.DsUnBind,
		nativead.Procs.DsBindingSetTimeout,
		nativead.Procs.DsReplicaGetInfo2W,
		nativead.Procs.DsReplicaFreeInfo,
	} {
		if err = api.InternalFind(proc); err != nil {
			return result, errors.Join(admodel.ErrUnsupported, err)
		}
	}
	var guid *win32.GUID
	switch root.Capabilities().Type {
	case admodel.DirectoryADDS:
	case admodel.DirectoryADLDS:
		if len(instance) != 16 {
			return result, admodel.ErrInvalidResult
		}
		guid = &win32.GUID{
			Data1: binary.LittleEndian.Uint32(instance),
			Data2: binary.LittleEndian.Uint16(instance[4:]),
			Data3: binary.LittleEndian.Uint16(instance[6:]),
		}
		copy(guid.Data4[:], instance[8:])
	default:
		return result, admodel.ErrUnsupportedDirectory
	}
	// Keep the caller's security identity through binding, synchronous queries,
	// unbinding and credential release. No background cancellation goroutine can
	// outlive either native owner.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	credential, err := api.InternalCredentials(config.Credentials)
	if credential != nil {
		defer api.InternalFreeCredentials(credential)
	}
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, context.Cause(ctx)) }()
	if err = context.Cause(ctx); err != nil {
		return result, err
	}
	var handle foundation.HANDLE
	status := api.InternalBind(&config.Endpoint.Host, nil, guid, nil, credential, nil, 0, &handle)
	defer func() {
		if handle != 0 {
			err = errors.Join(
				err,
				admodel.InternalNativeStatus("DsUnBindW", api.InternalUnBind(&handle)),
			)
		}
	}()
	if status != 0 {
		return result, admodel.InternalNativeStatus("DsBindByInstanceW", status)
	}
	if handle == 0 {
		return result, admodel.ErrInvalidNativeResult
	}
	for _, kind := range request.InternalKinds {
		wait, waitErr := InternalRemainingWait(ctx, config.Timeout)
		if waitErr != nil {
			result[kind] = admodel.InternalReplicationNativeReply{InternalErr: waitErr}
			continue
		}
		seconds := uint32((wait + time.Second - 1) / time.Second)
		if timeoutErr := admodel.InternalNativeStatus(
			"DsBindingSetTimeout",
			api.InternalSetTimeout(handle, seconds),
		); timeoutErr != nil {
			result[kind] = admodel.InternalReplicationNativeReply{InternalErr: timeoutErr}
			continue
		}
		var partition *string
		if kind == admodel.InternalReplicationNeighbors && request.InternalPartition != "" {
			partition = &request.InternalPartition
		}
		data, queryErr := admodel.InternalQueryReplicationInfo(
			ctx,
			api,
			handle,
			nativead.DS_REPL_INFO_TYPE(kind),
			partition,
		)
		result[kind] = admodel.InternalReplicationNativeReply{
			InternalData: data,
			InternalErr:  queryErr,
		}
	}
	return result, nil
}
