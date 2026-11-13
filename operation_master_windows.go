//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func (s *ldapSession) operationMasterModify(ctx context.Context, dn string, modifications []operationMasterModification) OperationMasterAttempt {
	return s.operationMasterModifyWith(ctx, dn, modifications, ldap.Ldap_modify_extW)
}

func (s *ldapSession) operationMasterModifyWith(ctx context.Context, dn string, modifications []operationMasterModification, modify ldapModifyFunc) OperationMasterAttempt {
	attempt := s.ldapModifyWith(ctx, dn, modifications, modify)
	result := OperationMasterAttempt{State: OperationMasterWriteState(attempt.State), Err: attempt.Err}
	if attempt.State == ldapWriteUncertain {
		result.Err = errors.Join(ErrOperationMasterUncertain, result.Err)
	}
	return result
}
