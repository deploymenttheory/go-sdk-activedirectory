package model

import (
	"fmt"
	"strings"
)

type InternalReplicationInfo uint32

const (
	InternalReplicationNeighbors         InternalReplicationInfo = 0
	InternalReplicationConnectFailures   InternalReplicationInfo = 3
	InternalReplicationLinkFailures      InternalReplicationInfo = 4
	InternalReplicationPendingOperations InternalReplicationInfo = 5
)

type InternalReplicationNativeData struct {
	InternalPartners   []ReplicationPartner
	InternalFailures   []ReplicationFailure
	InternalOperations []ReplicationQueueOperation
	InternalStarted    ReplicationTimestamp
}
type InternalReplicationNativeReply struct {
	InternalData InternalReplicationNativeData
	InternalErr  error
}
type InternalReplicationRequest struct {
	InternalKinds             []InternalReplicationInfo
	InternalOutbound          bool
	InternalPartition         string
	InternalServicePrincipals *ReplicationServicePrincipals
	InternalPortableIdentity  *InternalReplicationServiceIdentity
	InternalObserveRPC        func(ReplicationRPCProtection)
}

type InternalReplicationServerRead struct {
	InternalObservation ReplicationServerObservation
	InternalReplies     map[InternalReplicationInfo]InternalReplicationNativeReply
	InternalOutbound    ReplicationQueryState
	InternalPartners    []ReplicationPartner
	InternalObjects     []Object
}

func InternalReplicationState(err error) ReplicationQueryState {
	return ReplicationQueryState{
		Requested: true,
		Available: err == nil,
		Complete:  err == nil,
		Error:     err,
	}
}

func (reply InternalReplicationNativeReply) InternalState() ReplicationQueryState {
	state := InternalReplicationState(reply.InternalErr)
	state.Available = state.Available ||
		len(
			reply.InternalData.InternalPartners,
		)+len(
			reply.InternalData.InternalFailures,
		)+len(
			reply.InternalData.InternalOperations,
		) > 0 ||
		reply.InternalData.InternalStarted.Ticks != nil
	return state
}

func InternalValidateReplicationCredentials(credentials *Credentials) error {
	if err := InternalCredentialsValidate(credentials); err != nil {
		return err
	}
	if credentials == nil || credentials.Domain != "" {
		return nil
	}
	separator := strings.LastIndexAny(credentials.Username, "@\\")
	if separator <= 0 || separator == len(credentials.Username)-1 {
		return fmt.Errorf(
			"%w: replication RPC credentials require a domain or fully qualified username",
			ErrInvalidConfig,
		)
	}
	return nil
}
