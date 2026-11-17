package service_accounts

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// StartServiceAccountMigration links a delegated account to the account it
// supersedes and marks both started.
func (c *Service) StartServiceAccountMigration(
	ctx context.Context,
	request ServiceAccountMigrationRequest,
) (ServiceAccountMigrationResult, error) {
	return internalServiceChangeServiceAccountMigration(
		c,
		ctx,
		request,
		admodel.InternalMigrationStart,
	)
}

// CompleteServiceAccountMigration marks a started migration completed. It also
// disables the superseded account and removes its service principal names,
// which is the observed end state of the reference operation.
func (c *Service) CompleteServiceAccountMigration(
	ctx context.Context,
	request ServiceAccountMigrationRequest,
) (ServiceAccountMigrationResult, error) {
	return internalServiceChangeServiceAccountMigration(
		c,
		ctx,
		request,
		admodel.InternalMigrationComplete,
	)
}

// UndoServiceAccountMigration steps one stage back: a completed migration
// returns to started, and a started migration is unlinked.
//
// Undoing a completed migration does not re-enable the superseded account or
// restore its service principal names. The reference contract does not require
// it, so this SDK does not invent that restoration.
func (c *Service) UndoServiceAccountMigration(
	ctx context.Context,
	request ServiceAccountMigrationRequest,
) (ServiceAccountMigrationResult, error) {
	return internalServiceChangeServiceAccountMigration(
		c,
		ctx,
		request,
		admodel.InternalMigrationUndo,
	)
}

// ResetServiceAccountMigration unlinks the pair from either state, clearing
// both forward links and both states.
func (c *Service) ResetServiceAccountMigration(
	ctx context.Context,
	request ServiceAccountMigrationRequest,
) (ServiceAccountMigrationResult, error) {
	return internalServiceChangeServiceAccountMigration(
		c,
		ctx,
		request,
		admodel.InternalMigrationReset,
	)
}

func internalServiceChangeServiceAccountMigration(c *Service,
	ctx context.Context,
	request admodel.ServiceAccountMigrationRequest,
	operation admodel.InternalMigrationOperation,
) (admodel.ServiceAccountMigrationResult, error) {
	var result admodel.ServiceAccountMigrationResult
	if request.Identity.Form() == 0 || request.SupersededAccount.Form() == 0 {
		return result, errors.Join(admodel.ErrServiceAccountMigration, admodel.ErrInvalidIdentity)
	}
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()

	// Observe both accounts before planning. A transition is decided from what
	// the directory actually holds, never from the caller's assumption.
	var delegatedDN, supersededDN string
	err := adengine.InternalClientRead(c.engine(), bounded, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		if err := root.Capabilities().RequireADDS("ServiceAccountMigration"); err != nil {
			return err
		}
		options := admodel.ResolveIdentityOptions{
			Partition:  request.Partition,
			Properties: admodel.InternalDmsaProperties(),
		}
		result.Delegated.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Identity,
			options,
		)
		if err != nil {
			return err
		}
		// The delegated side must really be a dMSA: the superseded side may be
		// a user, computer or managed account, so only this one is class-checked.
		if err := admodel.InternalCentralAccessClassCheck(
			*result.Delegated.Observation.Object,
			admodel.InternalDmsaClass,
		); err != nil {
			return errors.Join(admodel.ErrServiceAccountMigration, err)
		}
		result.Superseded.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			request.SupersededAccount,
			options,
		)
		if err != nil {
			return err
		}
		delegatedDN = result.Delegated.Observation.Object.DistinguishedName
		supersededDN = result.Superseded.Observation.Object.DistinguishedName
		if admodel.InternalCentralSameDN(delegatedDN, supersededDN) {
			return errors.Join(admodel.ErrServiceAccountMigration, admodel.ErrInvalidIdentity)
		}
		delegatedSide, delegatedErr := admodel.InternalDecodeMigrationSide(
			*result.Delegated.Observation.Object,
			admodel.InternalDmsaStateAttribute,
			admodel.InternalDmsaPrecededByLink,
			admodel.InternalDmsaPrecededByLinkBL,
		)
		supersededSide, supersededErr := admodel.InternalDecodeMigrationSide(
			*result.Superseded.Observation.Object,
			admodel.InternalSupersededState,
			admodel.InternalSupersededLink,
			admodel.InternalSupersededLinkBL,
		)
		delegatedSide.Observation = result.Delegated.Observation
		supersededSide.Observation = result.Superseded.Observation
		result.Delegated, result.Superseded = delegatedSide, supersededSide
		return errors.Join(delegatedErr, supersededErr)
	})
	if err != nil {
		return result, err
	}

	plan, err := admodel.InternalPlanServiceAccountMigration(
		operation,
		result,
		delegatedDN,
		supersededDN,
	)
	if err != nil {
		return result, err
	}
	if admodel.InternalMigrationDisablesSuperseded(operation) {
		disable, err := admodel.InternalMigrationDisableChange(
			*result.Superseded.Observation.Object,
		)
		if err != nil {
			return result, err
		}
		plan.InternalSuperseded = append(plan.InternalSuperseded, disable)
	}

	// The two writes are separate modifies with no cross-object atomicity. The
	// delegated account is written first so a failure leaves the superseded
	// account untouched, and the partial state is reported rather than undone.
	// Address both accounts by GUID so a rename between the read and the write
	// cannot redirect either modify.
	delegatedGUID, err := admodel.InternalCentralAccessGUID(*result.Delegated.Observation.Object)
	if err != nil {
		return result, err
	}
	supersededGUID, err := admodel.InternalCentralAccessGUID(*result.Superseded.Observation.Object)
	if err != nil {
		return result, err
	}
	delegatedIdentity := admodel.InternalObjectGUIDIdentity(delegatedGUID)
	supersededIdentity := admodel.InternalObjectGUIDIdentity(supersededGUID)

	delegatedMutation, err := c.engine().
		UpdateObject(bounded, admodel.UpdateObjectRequest{
			Identity: delegatedIdentity,
			Changes:  plan.InternalDelegated,
			Options:  admodel.InternalMigrationOptions(request, admodel.InternalDmsaProperties()),
		})
	result.Delegated.Mutation = &delegatedMutation
	if err != nil {
		return result, err
	}

	supersededMutation, err := c.engine().
		UpdateObject(bounded, admodel.UpdateObjectRequest{
			Identity: supersededIdentity,
			Changes:  plan.InternalSuperseded,
			Options:  admodel.InternalMigrationOptions(request, admodel.InternalDmsaProperties()),
		})
	result.Superseded.Mutation = &supersededMutation
	if err != nil {
		// The first write stands. This is the partial-failure case the pair
		// cannot avoid, and it is surfaced, not compensated.
		result.Partial = true
		return result, errors.Join(admodel.ErrServiceAccountMigrationPartial, err)
	}

	result.Verified = delegatedMutation.Verified && supersededMutation.Verified
	result.Complete = result.Verified
	if !result.Verified {
		return result, admodel.ErrObjectReadback
	}
	return result, nil
}
