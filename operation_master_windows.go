//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

type operationMasterModifyFunc func(*ldap.LDAP, string, **ldap.LDAPModW, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32

func (s *ldapSession) operationMasterModify(ctx context.Context, dn string, modifications []operationMasterModification) OperationMasterAttempt {
	return s.operationMasterModifyWith(ctx, dn, modifications, ldap.Ldap_modify_extW)
}

func (s *ldapSession) operationMasterModifyWith(ctx context.Context, dn string, modifications []operationMasterModification, modify operationMasterModifyFunc) OperationMasterAttempt {
	if s.handle == nil {
		return OperationMasterAttempt{Err: ErrClosed}
	}
	if err := s.api.find(ldap.Procs.Ldap_modify_extW); err != nil {
		return OperationMasterAttempt{Err: fmt.Errorf("%w: %w", ErrUnsupported, err)}
	}
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return OperationMasterAttempt{Err: err}
	}
	if err := s.setTimeouts(wait); err != nil {
		return OperationMasterAttempt{Err: err}
	}
	// All values use bervals. This preserves binary SIDs and uses LDAP's UTF-8
	// octets for textual attribute values, without a UTF-16 reinterpretation.
	mods := make([]ldap.LDAPModW, len(modifications))
	values := make([]ldap.LDAP_BERVAL, len(modifications))
	valuePointers := make([][2]*ldap.LDAP_BERVAL, len(modifications))
	modPointers := make([]*ldap.LDAPModW, len(modifications)+1)
	for i, modification := range modifications {
		values[i] = ldap.LDAP_BERVAL{Bv_len: uint32(len(modification.value)), Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(modification.value)))}
		valuePointers[i][0] = &values[i]
		mods[i].Mod_op = modification.operation | ldap.LDAP_MOD_BVALUES
		mods[i].Mod_type = win32.UTF16Ptr(modification.attribute)
		*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mods[i].Mod_vals)) = &valuePointers[i][0]
		modPointers[i] = &mods[i]
	}
	if err := context.Cause(ctx); err != nil {
		return OperationMasterAttempt{Err: err}
	}
	var messageID uint32
	status := modify(s.handle, dn, &modPointers[0], nil, nil, &messageID)
	// WinLDAP copies asynchronous request inputs. Keep typed roots alive across
	// submission, including the pointer stored in the untyped C union.
	runtime.KeepAlive(modifications)
	runtime.KeepAlive(mods)
	runtime.KeepAlive(values)
	runtime.KeepAlive(valuePointers)
	runtime.KeepAlive(modPointers)
	if status != 0 {
		// A failed submission supplies no usable message ID. Conservatively
		// report uncertainty and retire the connection; never replay the write.
		return OperationMasterAttempt{State: OperationMasterWriteUncertain, Err: errors.Join(ErrOperationMasterUncertain, ldapStatus("ldap_modify_extW", status), context.Cause(ctx), s.close())}
	}
	return s.waitOperationMaster(ctx, messageID)
}

func (s *ldapSession) waitOperationMaster(ctx context.Context, messageID uint32) OperationMasterAttempt {
	for {
		wait, err := remainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return s.uncertainOperationMaster(messageID, nil, err)
		}
		timeout := nativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.api.result(s.handle, messageID, ldap.LDAP_MSG_ALL, &timeout, &message)
		if kind == 0 && message == nil {
			continue
		}
		if kind == math.MaxUint32 {
			err := s.sessionError("ldap_result(operation master)")
			if err == nil {
				err = ErrInvalidResult
			}
			return s.uncertainOperationMaster(messageID, message, errors.Join(err, context.Cause(ctx)))
		}
		if message == nil || kind != uint32(ldap.LDAP_RES_MODIFY) {
			return s.uncertainOperationMaster(messageID, message, fmt.Errorf("%w: unexpected operation master response", ErrInvalidResult))
		}
		return s.parseOperationMaster(ctx, message)
	}
}

func (s *ldapSession) uncertainOperationMaster(messageID uint32, message *ldap.LDAPMessage, cause error) OperationMasterAttempt {
	// Abandon does not undo a Modify that the server may already have applied.
	// Always retire the session, even when abandon succeeds.
	err := s.abandon(messageID, message, cause)
	return OperationMasterAttempt{State: OperationMasterWriteUncertain, Err: errors.Join(ErrOperationMasterUncertain, err, s.close())}
}

func (s *ldapSession) parseOperationMaster(ctx context.Context, message *ldap.LDAPMessage) (attempt OperationMasterAttempt) {
	retire := false
	defer func() {
		cleanup := ldapStatus("ldap_msgfree", s.api.messageFree(message))
		if cleanup != nil {
			attempt.Err = errors.Join(attempt.Err, cleanup)
			retire = true
		}
		if retire {
			attempt.Err = errors.Join(attempt.Err, s.close())
		}
		if cause := context.Cause(ctx); cause != nil {
			attempt.Err = errors.Join(attempt.Err, cause)
		}
	}()
	var code uint32
	var matchedDN, diagnostic foundation.PWSTR
	status := s.api.parseResult(s.handle, message, &code, &matchedDN, &diagnostic, nil, nil, 0)
	if matchedDN != nil {
		defer s.api.memoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.api.memoryFree(diagnostic)
	}
	if status != 0 {
		// Error outputs are owned allocations but not valid strings.
		attempt.State = OperationMasterWriteUncertain
		attempt.Err = errors.Join(ErrOperationMasterUncertain, ldapStatus("ldap_parse_resultW", status))
		retire = true
		return attempt
	}
	attempt.State = OperationMasterWriteAccepted
	serverError := &LDAPError{Operation: "operation master modify", Code: code}
	if code != 0 {
		attempt.State = OperationMasterWriteRejected
		attempt.Err = serverError
	}
	var matchedErr, diagnosticErr error
	serverError.MatchedDN, matchedErr = copyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = copyLDAPText(diagnostic)
	if matchedErr != nil || diagnosticErr != nil {
		attempt.Err = errors.Join(attempt.Err, matchedErr, diagnosticErr)
	}
	// WinLDAP local/transport errors are not a server acknowledgement, even
	// when surfaced by the result parser (LDAP_SERVER_DOWN through
	// LDAP_REFERRAL_LIMIT_EXCEEDED). These are WinLDAP's client error range.
	if code >= 81 && code <= 97 {
		attempt.State = OperationMasterWriteUncertain
		attempt.Err = errors.Join(ErrOperationMasterUncertain, attempt.Err)
		retire = true
	}
	return attempt
}
