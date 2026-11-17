//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalOperationMasterModify(
	ctx context.Context,
	dn string,
	modifications []admodel.InternalOperationMasterModification,
) admodel.OperationMasterAttempt {
	return s.InternalOperationMasterModifyWith(ctx, dn, modifications, ldap.Ldap_modify_extW)
}

func (s *InternalLdapSession) InternalOperationMasterModifyWith(
	ctx context.Context,
	dn string,
	modifications []admodel.InternalOperationMasterModification,
	modify InternalLdapModifyFunc,
) admodel.OperationMasterAttempt {
	attempt := s.InternalLdapModifyWith(ctx, dn, modifications, modify)
	result := admodel.OperationMasterAttempt{
		State: admodel.OperationMasterWriteState(attempt.State),
		Err:   attempt.Err,
	}
	if attempt.State == admodel.InternalLdapWriteUncertain {
		result.Err = errors.Join(admodel.ErrOperationMasterUncertain, result.Err)
	}
	return result
}
