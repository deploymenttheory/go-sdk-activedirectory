package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/epmwire"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/rpcdce"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/rpcwire"
	record "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/ssp/krb5/crypto"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalReadReplicationPortable(
	ctx context.Context,
	config admodel.Config,
	root admodel.RootDSE,
	instance []byte,
	request admodel.InternalReplicationRequest,
) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
	return InternalReadReplicationPortableWithDial(ctx, config, root, instance, request, &net.Dialer{})
}

// InternalReadReplicationPortableWithDial composes the actual direct portable
// diagnostic session for owned wire/lab qualification. The public dispatcher
// is enabled on the qualification branch after offline review. The dialer receives no credentials.
func InternalReadReplicationPortableWithDial(
	ctx context.Context, config admodel.Config, root admodel.RootDSE, instance []byte, request admodel.InternalReplicationRequest, dialer InternalPortableDialer,
) (replies map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, err error) {
	replies = make(map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, len(request.InternalKinds))
	defer func(observed context.Context) {
		err = errors.Join(err, context.Cause(observed))
		for _, kind := range request.InternalKinds {
			if _, present := replies[kind]; !present {
				// This category was not submitted. Do not assign a previous
				// query's authenticated status to it merely because RPC retired.
				replies[kind] = admodel.InternalReplicationNativeReply{InternalErr: errors.Join(admodel.ErrIncompleteResult, context.Cause(observed))}
			}
		}
	}(ctx)
	config, err = admodel.InternalConfigNormalized(config)
	if err != nil {
		return replies, err
	}
	if err = internalReplicationPortableRequest(config, root, instance, request, dialer); err != nil {
		return replies, err
	}
	if len(request.InternalKinds) == 0 {
		return replies, nil
	}
	principals := *request.InternalServicePrincipals
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()
	mapper, err := internalReplicationRPCBind(ctx, config, principals.EndpointMapper, 135, rpcwire.EndpointMapping, dialer)
	if err != nil {
		return replies, err
	}
	mapped, mapErr := mapper.MapDRSPort(ctx)
	internalObserveReplicationRPC(request, mapper, admodel.Endpoint{Host: config.Endpoint.Host, Port: 135}, "endpoint-map")
	closeErr := mapper.Close()
	if mapErr != nil || closeErr != nil {
		return replies, errors.Join(internalReplicationRPCFailure(mapErr), closeErr)
	}
	if mapped.MapStatus != 0 {
		return replies, internalReplicationRPCStatus("ept_map", mapped.MapStatus)
	}
	if mapped.FreeStatus != 0 {
		return replies, internalReplicationRPCStatus("ept_lookup_handle_free", mapped.FreeStatus)
	}
	if mapped.Port == 0 {
		return replies, admodel.ErrIncompleteResult
	}
	session, err := internalReplicationRPCBind(ctx, config, principals.DRS, mapped.Port, rpcwire.DirectoryReplication, dialer)
	if err != nil {
		return replies, err
	}
	defer func() { err = errors.Join(err, session.Close()) }()
	defer func() {
		internalObserveReplicationRPC(request, session, admodel.Endpoint{Host: config.Endpoint.Host, Port: mapped.Port}, "drs")
	}()
	bound, err := session.BindDiagnostics(ctx)
	if err != nil {
		return replies, internalReplicationRPCFailure(err)
	}
	if bound.Status != 0 {
		return replies, internalReplicationRPCStatus("IDL_DRSBind", bound.Status)
	}
	healthy := true
	defer func() {
		defer clear(bound.Handle[:])
		if healthy && context.Cause(ctx) == nil {
			status, unbindErr := session.UnbindDiagnostics(ctx, bound.Handle)
			err = errors.Join(err, internalReplicationRPCFailure(unbindErr), internalReplicationRPCStatus("IDL_DRSUnbind", status))
		}
	}()
	var objectDN *string
	if request.InternalPartition != "" {
		partition := request.InternalPartition
		objectDN = &partition
	}
	for _, kind := range request.InternalKinds {
		raw, queryErr := session.ReadReplicationInfo(ctx, bound.Handle, uint32(kind), objectDN)
		var reply admodel.InternalReplicationNativeReply
		if queryErr == nil || errors.Is(queryErr, drsrwire.ErrMalformedNDR) || errors.Is(queryErr, drsrwire.ErrNDRLimit) {
			reply = internalProjectReplicationRPC(ctx, kind, raw)
		}
		if queryErr != nil {
			healthy = false
			reply.InternalErr = errors.Join(reply.InternalErr, internalReplicationRPCFailure(queryErr))
		}
		replies[kind] = reply
		err = errors.Join(err, reply.InternalErr)
		if queryErr != nil {
			break
		}
	}
	return replies, err
}

func internalObserveReplicationRPC(request admodel.InternalReplicationRequest, session *rpcwire.Client, endpoint admodel.Endpoint, stage string) {
	if request.InternalObserveRPC == nil {
		return
	}
	protection := session.Protection()
	bits := uint32(128)
	if protection.EncryptionType == 18 {
		bits = 256
	}
	request.InternalObserveRPC(admodel.ReplicationRPCProtection{
		Stage: stage, Endpoint: endpoint, Realm: protection.Realm, ServicePrincipal: protection.ServicePrincipal,
		EncryptionType: protection.EncryptionType, CipherBits: bits, ExpiresAt: protection.ExpiresAt, MutualAuthentication: protection.MutualAuthentication,
		HeaderSigned: protection.ProtectedReply, Confidential: protection.ProtectedReply, Complete: protection.Complete,
	})
}

func internalReplicationRPCBind(
	ctx context.Context,
	config admodel.Config,
	principal string,
	port uint16,
	stage rpcwire.Stage,
	dialer InternalPortableDialer,
) (*rpcwire.Client, error) {
	kerberos := *config.Kerberos
	kerberos.SPN = principal
	stageConfig := config
	stageConfig.Kerberos = &kerberos
	krbConfig := internalPortableKerberosConfig(stageConfig)
	// Negotiate only implemented RPC record profiles, in one request. A cached
	// unsupported service key is refused; no second weaker request is made.
	krbConfig.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
	krbConfig.LibDefaults.DefaultTGSEnctypeIDs = []int32{18, 17}
	client, cleanup, err := internalPortableKerberosClient(ctx, stageConfig, krbConfig, dialer)
	if err != nil {
		return nil, internalPortableKerberosFailure(err)
	}
	defer cleanup()
	selected, err := client.GetServiceTicketWithValidity(principal) //nolint:contextcheck // This fresh client owns krbclient.WithContext(ctx); KDC sockets close on cancellation.
	if err != nil {
		return nil, internalPortableKerberosFailure(err)
	}
	defer clear(selected.Key.KeyValue)
	actor, err := rpcdce.NewClient(ctx, kerberos.Realm, types.NewPrincipalName(2, principal), client.Credentials.Realm(), client.Credentials.CName(), selected)
	if err != nil {
		return nil, internalReplicationRPCFailure(err)
	}
	defer actor.Destroy()
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(config.Endpoint.Host, strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return nil, errors.Join(admodel.ErrConnection, err)
	}
	session, err := rpcwire.Bind(ctx, connection, actor, stage, config.Timeout)
	if err != nil {
		return nil, internalReplicationRPCFailure(err)
	}
	return session, nil
}

func internalReplicationRPCStatus(operation string, status uint32) error {
	if status == 0 {
		return nil
	}
	err := error(&admodel.NativeStatusError{Operation: operation, Code: status})
	if status == 5 || status == 8453 {
		err = errors.Join(err, admodel.ErrReplicationPermission)
	}
	return err
}

func internalReplicationRPCFailure(err error) error {
	if err == nil {
		return nil
	}
	var fault *rpcwire.FaultError
	if errors.As(err, &fault) {
		return errors.Join(err, internalReplicationRPCStatus("protected RPC fault", fault.Status))
	}
	if errors.Is(err, rpcdce.ErrExpired) {
		return errors.Join(err, admodel.ErrKerberosExpired)
	}
	if errors.Is(err, rpcdce.ErrIdentity) || errors.Is(err, rpcdce.ErrAuthentication) {
		return admodel.InternalKerberosError(0, err)
	}
	if errors.Is(err, record.ErrUnsupportedProfile) {
		return errors.Join(
			err,
			&admodel.BackendUnavailableError{
				Backend:        admodel.BackendPortable,
				Authentication: admodel.AuthenticationKerberos,
				Feature:        "RPC requires an independently qualified AES17/18 record profile",
			},
		)
	}
	if errors.Is(err, drsrwire.ErrMalformedNDR) || errors.Is(err, drsrwire.ErrNDRLimit) || errors.Is(err, epmwire.ErrMalformed) {
		return errors.Join(admodel.ErrInvalidResult, err)
	}
	if errors.Is(err, epmwire.ErrNoEndpoint) {
		return errors.Join(
			err,
			&admodel.BackendUnavailableError{
				Backend:        admodel.BackendPortable,
				Authentication: admodel.AuthenticationKerberos,
				Feature:        "selected server has no authenticated DRS TCP endpoint",
			},
		)
	}
	if errors.Is(err, drsrwire.ErrUnsupportedServer) {
		return errors.Join(
			err,
			&admodel.BackendUnavailableError{
				Backend:        admodel.BackendPortable,
				Authentication: admodel.AuthenticationKerberos,
				Feature:        "server DRS replication information capability",
			},
		)
	}
	return fmt.Errorf("%w: protected replication RPC: %w", admodel.ErrConnection, err)
}
