//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

type ldapWriteAPI struct {
	add, modify ldapModifyFunc
	delete      func(*ldap.LDAP, string, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32
	rename      func(*ldap.LDAP, string, string, *string, int32, **ldap.LDAPControlW, **ldap.LDAPControlW, *uint32) uint32
}

func systemLDAPWriteAPI() ldapWriteAPI {
	return ldapWriteAPI{add: ldap.Ldap_add_extW, modify: ldap.Ldap_modify_extW, delete: ldap.Ldap_delete_extW, rename: ldap.Ldap_rename_extW}
}

func (s *ldapSession) ldapWrite(ctx context.Context, request ldapWriteRequest) ldapWriteAttempt {
	return s.ldapWriteWith(ctx, request, systemLDAPWriteAPI())
}

func (s *ldapSession) ldapWriteWith(ctx context.Context, request ldapWriteRequest, api ldapWriteAPI) ldapWriteAttempt {
	if err := validateLDAPWrite(request); err != nil {
		return ldapWriteAttempt{Err: err}
	}
	return s.submitLDAPWrite(ctx, request, api)
}

func validateLDAPWrite(request ldapWriteRequest) error {
	if request.operation > ldapWriteRename || !utf8.ValidString(request.dn) || strings.ContainsRune(request.dn, 0) {
		return ErrInvalidResult
	}
	if request.operation != ldapWriteModify && request.dn == "" {
		return ErrInvalidResult
	}
	if request.operation == ldapWriteRename {
		if request.newRDN == "" || !utf8.ValidString(request.newRDN) || strings.ContainsRune(request.newRDN, 0) {
			return ErrInvalidResult
		}
	} else if request.newRDN != "" || request.deleteOldRDN {
		return ErrInvalidResult
	}
	if request.operation == ldapWriteAdd || request.operation == ldapWriteModify {
		if len(request.modifications) == 0 {
			return ErrInvalidResult
		}
	} else if len(request.modifications) != 0 {
		return ErrInvalidResult
	}
	for _, mod := range request.modifications {
		if !attributeDescription.MatchString(mod.attribute) || mod.operation > 2 || (request.operation == ldapWriteAdd && mod.operation != 0) || (len(mod.values) == 0 && mod.operation != 1) {
			return ErrInvalidResult
		}
		for _, value := range mod.values {
			if uint64(len(value)) > math.MaxUint32 {
				return ErrInvalidResult
			}
		}
	}
	for _, control := range request.controls {
		if !validLDAPWriteOID(control.oid) || uint64(len(control.value)) > math.MaxUint32 {
			return ErrInvalidResult
		}
	}
	return nil
}

func validLDAPWriteOID(oid string) bool {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// Typed roots are retained through synchronous request encoding. In particular,
// LDAPMod's untyped C union cannot be the only root of its berval pointers.
type ldapWriteInputs struct {
	mods            []ldap.LDAPModW
	values          [][]ldap.LDAP_BERVAL
	valuePointers   [][]*ldap.LDAP_BERVAL
	modPointers     []*ldap.LDAPModW
	controls        []ldap.LDAPControlW
	controlPointers []*ldap.LDAPControlW
}

func makeLDAPWriteInputs(request ldapWriteRequest) ldapWriteInputs {
	inputs := ldapWriteInputs{mods: make([]ldap.LDAPModW, len(request.modifications)), values: make([][]ldap.LDAP_BERVAL, len(request.modifications)), valuePointers: make([][]*ldap.LDAP_BERVAL, len(request.modifications)), modPointers: make([]*ldap.LDAPModW, len(request.modifications)+1)}
	for i, mod := range request.modifications {
		inputs.mods[i].Mod_op = mod.operation | ldap.LDAP_MOD_BVALUES
		inputs.mods[i].Mod_type = win32.UTF16Ptr(mod.attribute)
		inputs.modPointers[i] = &inputs.mods[i]
		if len(mod.values) == 0 {
			continue
		} // NULL union means whole-attribute delete.
		inputs.values[i] = make([]ldap.LDAP_BERVAL, len(mod.values))
		inputs.valuePointers[i] = make([]*ldap.LDAP_BERVAL, len(mod.values)+1)
		for j, value := range mod.values {
			inputs.values[i][j] = ldap.LDAP_BERVAL{Bv_len: uint32(len(value)), Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(value)))}
			inputs.valuePointers[i][j] = &inputs.values[i][j]
		}
		*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&inputs.mods[i].Mod_vals)) = &inputs.valuePointers[i][0]
	}
	if len(request.controls) > 0 {
		inputs.controls = make([]ldap.LDAPControlW, len(request.controls))
		inputs.controlPointers = make([]*ldap.LDAPControlW, len(request.controls)+1)
		for i, control := range request.controls {
			inputs.controls[i].Ldctl_oid = win32.UTF16Ptr(control.oid)
			inputs.controls[i].Ldctl_value = ldap.LDAP_BERVAL{Bv_len: uint32(len(control.value)), Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(control.value)))}
			if control.critical {
				inputs.controls[i].Ldctl_iscritical = 1
			}
			inputs.controlPointers[i] = &inputs.controls[i]
		}
	}
	return inputs
}

func ldapWriteProtocol(operation ldapWriteOperation) (*win32.Proc, string, string, uint32) {
	switch operation {
	case ldapWriteAdd:
		return ldap.Procs.Ldap_add_extW, "LDAP add", "ldap_add_extW", uint32(ldap.LDAP_RES_ADD)
	case ldapWriteDelete:
		return ldap.Procs.Ldap_delete_extW, "LDAP delete", "ldap_delete_extW", uint32(ldap.LDAP_RES_DELETE)
	case ldapWriteRename:
		return ldap.Procs.Ldap_rename_extW, "LDAP rename", "ldap_rename_extW", uint32(ldap.LDAP_RES_MODRDN)
	default:
		return ldap.Procs.Ldap_modify_extW, "LDAP modify", "ldap_modify_extW", uint32(ldap.LDAP_RES_MODIFY)
	}
}

func (s *ldapSession) submitLDAPWrite(ctx context.Context, request ldapWriteRequest, api ldapWriteAPI) ldapWriteAttempt {
	if s.handle == nil {
		return ldapWriteAttempt{Err: ErrClosed}
	}
	proc, operation, nativeOperation, response := ldapWriteProtocol(request.operation)
	if err := s.api.find(proc); err != nil {
		return ldapWriteAttempt{Err: fmt.Errorf("%w: %w", ErrUnsupported, err)}
	}
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return ldapWriteAttempt{Err: err}
	}
	if err := s.setTimeouts(wait); err != nil {
		return ldapWriteAttempt{Err: err}
	}
	inputs := makeLDAPWriteInputs(request)
	if err := context.Cause(ctx); err != nil {
		return ldapWriteAttempt{Err: err}
	}
	var controls **ldap.LDAPControlW
	if len(inputs.controlPointers) > 0 {
		controls = &inputs.controlPointers[0]
	}
	var messageID, status uint32
	switch request.operation {
	case ldapWriteAdd:
		status = api.add(s.handle, request.dn, &inputs.modPointers[0], controls, nil, &messageID)
	case ldapWriteDelete:
		status = api.delete(s.handle, request.dn, controls, nil, &messageID)
	case ldapWriteRename:
		var deleteOld int32
		if request.deleteOldRDN {
			deleteOld = 1
		}
		// A nil NewParent keeps the object in the same parent container.
		status = api.rename(s.handle, request.dn, request.newRDN, nil, deleteOld, controls, nil, &messageID)
	default:
		status = api.modify(s.handle, request.dn, &inputs.modPointers[0], controls, nil, &messageID)
	}
	runtime.KeepAlive(request)
	runtime.KeepAlive(inputs)
	if status != 0 {
		// No usable message ID was returned. Do not infer whether the server
		// applied the request, reconnect, chase referrals, or replay the write.
		return ldapWriteAttempt{State: ldapWriteUncertain, Err: errors.Join(errLDAPWriteUncertain, ldapStatus(nativeOperation, status), context.Cause(ctx), s.close())}
	}
	return s.waitLDAPWrite(ctx, messageID, response, operation)
}

func (s *ldapSession) waitLDAPWrite(ctx context.Context, messageID, response uint32, operation string) ldapWriteAttempt {
	for {
		wait, err := remainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return s.uncertainLDAPWrite(messageID, nil, err)
		}
		timeout := nativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.api.result(s.handle, messageID, ldap.LDAP_MSG_ALL, &timeout, &message)
		if kind == 0 && message == nil {
			continue
		}
		if kind == math.MaxUint32 {
			err := s.sessionError("ldap_result(LDAP)")
			if err == nil {
				err = ErrInvalidResult
			}
			return s.uncertainLDAPWrite(messageID, message, errors.Join(err, context.Cause(ctx)))
		}
		if message == nil || kind != response {
			return s.uncertainLDAPWrite(messageID, message, fmt.Errorf("%w: unexpected LDAP response", ErrInvalidResult))
		}
		return s.parseLDAPWrite(ctx, message, operation)
	}
}

func (s *ldapSession) uncertainLDAPWrite(messageID uint32, message *ldap.LDAPMessage, cause error) ldapWriteAttempt {
	// Abandon does not undo a write that the server may already have applied.
	// Always retire the session, even when abandon succeeds.
	err := s.abandon(messageID, message, cause)
	return ldapWriteAttempt{State: ldapWriteUncertain, Err: errors.Join(errLDAPWriteUncertain, err, s.close())}
}

func (s *ldapSession) parseLDAPWrite(ctx context.Context, message *ldap.LDAPMessage, operation string) (attempt ldapWriteAttempt) {
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
		attempt.State = ldapWriteUncertain
		attempt.Err = errors.Join(errLDAPWriteUncertain, ldapStatus("ldap_parse_resultW", status))
		retire = true
		return attempt
	}
	attempt.State = ldapWriteAccepted
	serverError := &LDAPError{Operation: operation, Code: code}
	if code != 0 {
		attempt.State = ldapWriteRejected
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
		attempt.State = ldapWriteUncertain
		attempt.Err = errors.Join(errLDAPWriteUncertain, attempt.Err)
		retire = true
	}
	return attempt
}
