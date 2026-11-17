package directory_settings

import (
	"context"
	"errors"
	"strings"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// EnableOptionalFeature uses one documented rootDSE ADD on the pinned endpoint.
// Preflight and readback share the client gate. No role transfer, reconnect,
// referral, automatic retry or rollback occurs. Known irreversible features,
// and any feature without the disablable flag, require explicit acknowledgement.
func (c *Service) EnableOptionalFeature(
	ctx context.Context,
	request OptionalFeatureChangeRequest,
) (OptionalFeatureChangeResult, error) {
	return internalServiceChangeOptionalFeature(c, ctx, request, true)
}

// DisableOptionalFeature rejects irreversible features before native submission.
// A missing response is uncertain; callers must reconcile before another write.
func (c *Service) DisableOptionalFeature(
	ctx context.Context,
	request OptionalFeatureChangeRequest,
) (OptionalFeatureChangeResult, error) {
	return internalServiceChangeOptionalFeature(c, ctx, request, false)
}

func internalServiceChangeOptionalFeature(c *Service,
	ctx context.Context,
	request admodel.OptionalFeatureChangeRequest,
	enable bool,
) (admodel.OptionalFeatureChangeResult, error) {
	result := admodel.OptionalFeatureChangeResult{
		Scope:   request.Scope,
		ScopeDN: request.ScopeDN,
		Enable:  enable,
	}
	if err := request.Validate(); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(bounded context.Context) error {
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalLdapModifySession)
		if !ok {
			return admodel.ErrUnsupported
		}
		if err := admodel.InternalPrepareOptionalFeatureChange(
			bounded,
			session,
			request,
			enable,
			&result,
		); err != nil {
			return err
		}
		if err := context.Cause(bounded); err != nil {
			return err
		}
		attribute := "disableOptionalFeature"
		if enable {
			attribute = "enableOptionalFeature"
		}
		attempt := session.InternalLdapModify(
			bounded,
			"",
			[]admodel.InternalLdapModification{
				{
					InternalOperation: 0,
					InternalAttribute: attribute,
					InternalValue:     []byte(result.ScopeDN + ":" + *result.Feature.FeatureGUID),
				},
			},
		)
		result.WriteState = admodel.OptionalFeatureWriteState(attempt.State)
		result.WriteError = attempt.Err
		if attempt.State == admodel.InternalLdapWriteUncertain {
			result.WriteError = errors.Join(admodel.ErrOptionalFeatureUncertain, attempt.Err)
			return result.WriteError
		}
		if attempt.State != admodel.InternalLdapWriteAccepted {
			if attempt.Err == nil {
				return admodel.ErrInvalidResult
			}
			return attempt.Err
		}
		// Accepted remains accepted even if cleanup/cancellation prevents readback.
		if attempt.Err != nil {
			return attempt.Err
		}
		attrs, err := session.InternalBaseObject(
			bounded,
			result.ScopeDN,
			[]string{"distinguishedName", "objectClass", "msDS-EnabledFeature"},
		)
		if err != nil {
			return errors.Join(admodel.ErrOptionalFeatureReadback, err)
		}
		if dn, err := admodel.InternalOperationMasterObject(
			attrs,
			admodel.InternalOptionalFeatureScopeClass(request.Scope),
		); err != nil ||
			!strings.EqualFold(dn, result.ScopeDN) {
			return errors.Join(admodel.ErrOptionalFeatureReadback, err)
		}
		result.AfterEnabled, err = admodel.InternalOptionalFeatureEnabled(
			attrs,
			result.Feature.DistinguishedName,
		)
		result.Verified = err == nil && result.AfterEnabled != nil && *result.AfterEnabled == enable
		if !result.Verified {
			return errors.Join(admodel.ErrOptionalFeatureReadback, err)
		}
		return nil
	})
	var native *admodel.LDAPError
	if errors.As(err, &native) && native.Code == 50 {
		err = errors.Join(admodel.ErrOptionalFeaturePermission, err)
	}
	return result, err
}
