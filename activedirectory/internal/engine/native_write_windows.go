//go:build windows && (amd64 || arm64)

package engine

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
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalLdapWriteAPI struct {
	InternalAdd, InternalModify InternalLdapModifyFunc
	InternalDelete              func(*ldap.LDAP, string, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32
	InternalRename              func(*ldap.LDAP, string, string, *string, int32, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32
}

func InternalSystemLDAPWriteAPI() InternalLdapWriteAPI {
	return InternalLdapWriteAPI{
		InternalAdd:    ldap.Ldap_add_extW,
		InternalModify: ldap.Ldap_modify_extW,
		InternalDelete: ldap.Ldap_delete_extW,
		InternalRename: ldap.Ldap_rename_extW,
	}
}

func (s *InternalLdapSession) InternalLdapWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
) admodel.InternalLdapWriteAttempt {
	return s.InternalLdapWriteWith(ctx, request, InternalSystemLDAPWriteAPI())
}

func (s *InternalLdapSession) InternalLdapWriteWith(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
	api InternalLdapWriteAPI,
) admodel.InternalLdapWriteAttempt {
	if err := InternalValidateLDAPWrite(request); err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	return s.InternalSubmitLDAPWrite(ctx, request, api)
}

// Typed roots are retained through synchronous request encoding. In particular,
// LDAPMod's untyped C union cannot be the only root of its berval pointers.
type InternalLdapWriteInputs struct {
	InternalMods            []ldap.LDAPModW
	InternalValues          [][]ldap.LDAP_BERVAL
	InternalValuePointers   [][]*ldap.LDAP_BERVAL
	InternalModPointers     []*ldap.LDAPModW
	InternalControls        []ldap.LDAPControlW
	InternalControlPointers []*ldap.LDAPControlW
}

func InternalMakeLDAPWriteInputs(request admodel.InternalLdapWriteRequest) (InternalLdapWriteInputs, error) {
	inputs := InternalLdapWriteInputs{
		InternalMods:          make([]ldap.LDAPModW, len(request.InternalModifications)),
		InternalValues:        make([][]ldap.LDAP_BERVAL, len(request.InternalModifications)),
		InternalValuePointers: make([][]*ldap.LDAP_BERVAL, len(request.InternalModifications)),
		InternalModPointers:   make([]*ldap.LDAPModW, len(request.InternalModifications)+1),
	}
	for i, mod := range request.InternalModifications {
		inputs.InternalMods[i].Mod_op = mod.InternalOperation | ldap.LDAP_MOD_BVALUES
		inputs.InternalMods[i].Mod_type = win32.UTF16Ptr(mod.InternalAttribute)
		inputs.InternalModPointers[i] = &inputs.InternalMods[i]
		if len(mod.InternalValues) == 0 {
			continue
		} // NULL union means whole-attribute delete.
		inputs.InternalValues[i] = make([]ldap.LDAP_BERVAL, len(mod.InternalValues))
		inputs.InternalValuePointers[i] = make([]*ldap.LDAP_BERVAL, len(mod.InternalValues)+1)
		for j, value := range mod.InternalValues {
			length := int64(len(value))
			if length < 0 || length > math.MaxUint32 {
				return InternalLdapWriteInputs{}, admodel.ErrInvalidResult
			}
			inputs.InternalValues[i][j] = ldap.LDAP_BERVAL{
				Bv_len: uint32(length),
				Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(value))),
			}
			inputs.InternalValuePointers[i][j] = &inputs.InternalValues[i][j]
		}
		*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&inputs.InternalMods[i].Mod_vals)) = &inputs.InternalValuePointers[i][0]
	}
	if len(request.InternalControls) > 0 {
		inputs.InternalControls = make([]ldap.LDAPControlW, len(request.InternalControls))
		inputs.InternalControlPointers = make([]*ldap.LDAPControlW, len(request.InternalControls)+1)
		for i, control := range request.InternalControls {
			length := int64(len(control.InternalValue))
			if length < 0 || length > math.MaxUint32 {
				return InternalLdapWriteInputs{}, admodel.ErrInvalidResult
			}
			inputs.InternalControls[i].Ldctl_oid = win32.UTF16Ptr(control.InternalOid)
			inputs.InternalControls[i].Ldctl_value = ldap.LDAP_BERVAL{
				Bv_len: uint32(length),
				Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(control.InternalValue))),
			}
			if control.InternalCritical {
				inputs.InternalControls[i].Ldctl_iscritical = 1
			}
			inputs.InternalControlPointers[i] = &inputs.InternalControls[i]
		}
	}
	return inputs, nil
}

func InternalLdapWriteProtocol(
	operation admodel.InternalLdapWriteOperation,
) (*win32.Proc, string, string, uint32) {
	switch operation {
	case admodel.InternalLdapWriteAdd:
		return ldap.Procs.Ldap_add_extW, "LDAP add", "ldap_add_extW", uint32(ldap.LDAP_RES_ADD)
	case admodel.InternalLdapWriteDelete:
		return ldap.Procs.Ldap_delete_extW, "LDAP delete", "ldap_delete_extW", uint32(
			ldap.LDAP_RES_DELETE,
		)
	case admodel.InternalLdapWriteRename:
		return ldap.Procs.Ldap_rename_extW, "LDAP rename", "ldap_rename_extW", uint32(
			ldap.LDAP_RES_MODRDN,
		)
	default:
		return ldap.Procs.Ldap_modify_extW, "LDAP modify", "ldap_modify_extW", uint32(
			ldap.LDAP_RES_MODIFY,
		)
	}
}

func (s *InternalLdapSession) InternalSubmitLDAPWrite(
	ctx context.Context,
	request admodel.InternalLdapWriteRequest,
	api InternalLdapWriteAPI,
) admodel.InternalLdapWriteAttempt {
	if s.InternalHandle == nil {
		return admodel.InternalLdapWriteAttempt{Err: admodel.ErrClosed}
	}
	proc, operation, nativeOperation, response := InternalLdapWriteProtocol(
		request.InternalOperation,
	)
	if err := s.InternalApi.InternalFind(proc); err != nil {
		return admodel.InternalLdapWriteAttempt{
			Err: fmt.Errorf("%w: %w", admodel.ErrUnsupported, err),
		}
	}
	wait, err := InternalRemainingWait(ctx, s.InternalTimeout)
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	if err := s.InternalSetTimeouts(wait); err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	inputs, err := InternalMakeLDAPWriteInputs(request)
	if err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	if err := context.Cause(ctx); err != nil {
		return admodel.InternalLdapWriteAttempt{Err: err}
	}
	var controls **ldap.LDAPControlW
	if len(inputs.InternalControlPointers) > 0 {
		controls = &inputs.InternalControlPointers[0]
	}
	var messageID, status uint32
	switch request.InternalOperation {
	case admodel.InternalLdapWriteAdd:
		status = api.InternalAdd(
			s.InternalHandle,
			request.InternalDn,
			&inputs.InternalModPointers[0],
			controls,
			nil,
			&messageID,
		)
	case admodel.InternalLdapWriteDelete:
		status = api.InternalDelete(s.InternalHandle, request.InternalDn, controls, nil, &messageID)
	case admodel.InternalLdapWriteRename:
		var deleteOld int32
		if request.InternalDeleteOldRDN {
			deleteOld = 1
		}
		var parent *string
		if request.InternalNewParent != "" {
			parent = &request.InternalNewParent
		}
		// Ordinary renames retain nil; typed topology moves supply a resolved parent.
		status = api.InternalRename(
			s.InternalHandle,
			request.InternalDn,
			request.InternalNewRDN,
			parent,
			deleteOld,
			controls,
			nil,
			&messageID,
		)
	default:
		status = api.InternalModify(
			s.InternalHandle,
			request.InternalDn,
			&inputs.InternalModPointers[0],
			controls,
			nil,
			&messageID,
		)
	}
	runtime.KeepAlive(request)
	runtime.KeepAlive(inputs)
	if status != 0 {
		// No usable message ID was returned. Do not infer whether the server
		// applied the request, reconnect, chase referrals, or replay the write.
		return admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteUncertain,
			Err: errors.Join(
				admodel.InternalLDAPWriteUncertainError(),
				InternalLdapStatus(nativeOperation, status),
				context.Cause(ctx),
				s.InternalClose(),
			),
		}
	}
	return s.InternalWaitLDAPWrite(ctx, messageID, response, operation)
}

func (s *InternalLdapSession) InternalWaitLDAPWrite(
	ctx context.Context,
	messageID, response uint32,
	operation string,
) admodel.InternalLdapWriteAttempt {
	for {
		wait, err := InternalRemainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return s.InternalUncertainLDAPWrite(messageID, nil, err)
		}
		timeout := InternalNativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.InternalApi.InternalResult(
			s.InternalHandle,
			messageID,
			ldap.LDAP_MSG_ALL,
			&timeout,
			&message,
		)
		if kind == 0 && message == nil {
			continue
		}
		if kind == math.MaxUint32 {
			err := s.InternalSessionError("ldap_result(LDAP)")
			if err == nil {
				err = admodel.ErrInvalidResult
			}
			return s.InternalUncertainLDAPWrite(
				messageID,
				message,
				errors.Join(err, context.Cause(ctx)),
			)
		}
		if message == nil || kind != response {
			return s.InternalUncertainLDAPWrite(
				messageID,
				message,
				fmt.Errorf("%w: unexpected LDAP response", admodel.ErrInvalidResult),
			)
		}
		return s.InternalParseLDAPWrite(ctx, message, operation)
	}
}

func (s *InternalLdapSession) InternalUncertainLDAPWrite(
	messageID uint32,
	message *ldap.LDAPMessage,
	cause error,
) admodel.InternalLdapWriteAttempt {
	// Abandon does not undo a write that the server may already have applied.
	// Always retire the session, even when abandon succeeds.
	err := s.InternalAbandon(messageID, message, cause)
	return admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteUncertain,
		Err:   errors.Join(admodel.InternalLDAPWriteUncertainError(), err, s.InternalClose()),
	}
}

func (s *InternalLdapSession) InternalParseLDAPWrite(
	ctx context.Context,
	message *ldap.LDAPMessage,
	operation string,
) (attempt admodel.InternalLdapWriteAttempt) {
	retire := false
	defer func() {
		cleanup := InternalLdapStatus("ldap_msgfree", s.InternalApi.InternalMessageFree(message))
		if cleanup != nil {
			attempt.Err = errors.Join(attempt.Err, cleanup)
			retire = true
		}
		if retire {
			attempt.Err = errors.Join(attempt.Err, s.InternalClose())
		}
		if cause := context.Cause(ctx); cause != nil {
			attempt.Err = errors.Join(attempt.Err, cause)
		}
	}()
	var code uint32
	var matchedDN, diagnostic foundation.PWSTR
	status := s.InternalApi.InternalParseResult(
		s.InternalHandle,
		message,
		&code,
		&matchedDN,
		&diagnostic,
		nil,
		nil,
		0,
	)
	if matchedDN != nil {
		defer s.InternalApi.InternalMemoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.InternalApi.InternalMemoryFree(diagnostic)
	}
	if status != 0 {
		// Error outputs are owned allocations but not valid strings.
		attempt.State = admodel.InternalLdapWriteUncertain
		attempt.Err = errors.Join(
			admodel.InternalLDAPWriteUncertainError(),
			InternalLdapStatus("ldap_parse_resultW", status),
		)
		retire = true
		return attempt
	}
	attempt.State = admodel.InternalLdapWriteAccepted
	serverError := &admodel.LDAPError{Operation: operation, Code: code}
	if code != 0 {
		attempt.State = admodel.InternalLdapWriteRejected
		attempt.Err = serverError
	}
	var matchedErr, diagnosticErr error
	serverError.MatchedDN, matchedErr = InternalCopyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = InternalCopyLDAPText(diagnostic)
	if matchedErr != nil || diagnosticErr != nil {
		attempt.Err = errors.Join(attempt.Err, matchedErr, diagnosticErr)
	}
	// WinLDAP local/transport errors are not a server acknowledgement, even
	// when surfaced by the result parser (LDAP_SERVER_DOWN through
	// LDAP_REFERRAL_LIMIT_EXCEEDED). These are WinLDAP's client error range.
	if code >= 81 && code <= 97 {
		attempt.State = admodel.InternalLdapWriteUncertain
		attempt.Err = errors.Join(admodel.InternalLDAPWriteUncertainError(), attempt.Err)
		retire = true
	}
	return attempt
}
