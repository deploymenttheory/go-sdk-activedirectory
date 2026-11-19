package engine

import (
	"context"
	"errors"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/drsrwire"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalProjectReplicationRPC(ctx context.Context, kind admodel.InternalReplicationInfo, raw drsrwire.Reply) admodel.InternalReplicationNativeReply {
	observation := admodel.InternalPortableReplicationReply{
		Kind:    admodel.InternalReplicationInfo(raw.Kind),
		Status:  raw.Status,
		Present: raw.Present,
		Count:   raw.Count,
		Started: raw.Started,
	}
	for _, row := range raw.Neighbors {
		observation.Neighbors = append(observation.Neighbors, admodel.InternalPortableReplicationNeighbor{
			PartitionDN: row.PartitionDN, PartnerDN: row.PartnerDN, PartnerAddress: row.PartnerAddress, TransportDN: row.TransportDN,
			PartitionGUID: row.PartitionGUID, PartnerGUID: row.PartnerGUID, InvocationID: row.InvocationID, TransportGUID: row.TransportGUID,
			ReplicaFlags: row.ReplicaFlags, LastObjectUSN: row.LastObjectUSN, AttributeFilterUSN: row.AttributeFilterUSN,
			LastSuccess: row.LastSuccess, LastAttempt: row.LastAttempt, LastResult: row.LastResult, ConsecutiveFailures: row.ConsecutiveFailures,
		})
	}
	for _, row := range raw.Failures {
		observation.Failures = append(
			observation.Failures,
			admodel.InternalPortableReplicationFailure{
				PartnerDN:    row.PartnerDN,
				PartnerGUID:  row.PartnerGUID,
				Time:         row.Time,
				FailureCount: row.FailureCount,
				LastResult:   row.LastResult,
			},
		)
	}
	for _, row := range raw.Operations {
		observation.Operations = append(observation.Operations, admodel.InternalPortableReplicationOperation{
			PartitionDN: row.PartitionDN, PartnerDN: row.PartnerDN, PartnerAddress: row.PartnerAddress, PartitionGUID: row.PartitionGUID, PartnerGUID: row.PartnerGUID,
			Enqueued: row.Enqueued, SerialNumber: row.SerialNumber, Priority: row.Priority, Type: row.Type, Options: row.Options,
		})
	}
	reply := admodel.InternalDecodePortableReplicationObservation(ctx, kind, observation)
	if raw.Status != 0 {
		reply.InternalErr = errors.Join(reply.InternalErr, internalReplicationRPCStatus("IDL_DRSGetReplInfo", raw.Status))
	}
	return reply
}
