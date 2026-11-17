package operation_master

import (
	"context"
	"fmt"
	"slices"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// MoveOperationMasterRoles transfers the selected roles to this connection's
// server using native WinLDAP. It validates the directory, target DSA, and all
// selected role objects before writing. AD LDS accepts schema and naming roles
// only. An RODC, an unsynchronized server, or an unknown directory is rejected.
//
// Force permits an explicit seizure after an acknowledged operationsError,
// unavailable, or unwillingToPerform transfer response and a fresh readback.
// Other failures stop the request. No write is retried, no referral is followed,
// and no reconnect occurs. Loss of a write response retires the connection.
// Cancellation/Close after submission can leave an uncertain write; callers
// must reconcile directory state themselves before making another request.
func (c *Service) MoveOperationMasterRoles(
	ctx context.Context,
	request MoveOperationMasterRolesRequest,
) (MoveOperationMasterRolesResult, error) {
	var result admodel.MoveOperationMasterRolesResult
	if err := request.Validate(); err != nil {
		return result, err
	}
	roles := slices.Clone(request.Roles)
	result.Outcomes = make([]admodel.OperationMasterOutcome, len(roles))
	for i, role := range roles {
		result.Outcomes[i] = admodel.OperationMasterOutcome{
			Role:   role,
			Status: admodel.OperationMasterNotAttempted,
		}
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(bounded context.Context) error {
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalOperationMasterSession)
		if !ok {
			return admodel.ErrUnsupported
		}
		target, plans, err := admodel.InternalPrepareOperationMasters(bounded, session, roles)
		result.TargetDSA = target
		if err != nil {
			return admodel.InternalOperationMasterError(err)
		}
		for i, plan := range plans {
			outcome := &result.Outcomes[i]
			outcome.RoleObjectDN, outcome.PreviousOwnerDN = plan.InternalDn, plan.InternalOwner
			outcome.PreviousRIDPool = plan.InternalRidPool
		}
		for i, plan := range plans {
			if err := context.Cause(bounded); err != nil {
				return err
			}
			outcome := &result.Outcomes[i]
			admodel.InternalMoveOperationMaster(
				bounded,
				session,
				target,
				plan,
				request.Force,
				outcome,
			)
			if outcome.Err != nil {
				return fmt.Errorf("%s: %w", plan.InternalRole, outcome.Err)
			}
		}
		return nil
	})
	return result, err
}
