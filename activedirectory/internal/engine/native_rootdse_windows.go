//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalBaseObject(
	ctx context.Context,
	base string,
	attributes []string,
) (map[string][][]byte, error) {
	return s.InternalBaseObjectRead(ctx, base, attributes, s.InternalReadMessage)
}

func (s *InternalLdapSession) InternalRangedBaseObject(
	ctx context.Context,
	base string,
	attributes []string,
) (map[string][][]byte, error) {
	return s.InternalBaseObjectRead(
		ctx,
		base,
		attributes,
		func(message *ldap.LDAPMessage) (map[string][][]byte, error) {
			return s.InternalReadMessageAttributes(
				message,
				func(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
					return s.InternalReadAttributeProjection(entry, true, true)
				},
			)
		},
	)
}

func (s *InternalLdapSession) InternalBaseObjectRead(
	ctx context.Context,
	base string,
	attributes []string,
	read func(*ldap.LDAPMessage) (map[string][][]byte, error),
) (map[string][][]byte, error) {
	return s.InternalBaseObjectReadControls(ctx, base, attributes, nil, read)
}

func (s *InternalLdapSession) InternalBaseObjectReadControls(
	ctx context.Context,
	base string,
	attributes []string,
	controls []*ldap.LDAPControlW,
	read func(*ldap.LDAPMessage) (map[string][][]byte, error),
) (map[string][][]byte, error) {
	if s.InternalHandle == nil {
		return nil, admodel.ErrClosed
	}
	wait, err := InternalRemainingWait(ctx, s.InternalTimeout)
	if err != nil {
		return nil, err
	}
	if err := s.InternalSetTimeouts(wait); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("LDAP base-object read cancelled: %w", err)
	}
	pointers := make([]*uint16, len(attributes)+1)
	for i, name := range attributes {
		pointers[i] = win32.UTF16Ptr(name)
	}
	var messageID uint32
	var serverControls **ldap.LDAPControlW
	if len(controls) != 0 {
		serverControls = &controls[0]
	}
	status := s.InternalApi.InternalSearch(
		s.InternalHandle,
		&base,
		ldap.LDAP_SCOPE_BASE,
		"(objectClass=*)",
		&pointers[0],
		0,
		serverControls,
		nil,
		InternalSecondsCeiling(wait),
		0,
		&messageID,
	)
	// The pointer array and every string remain typed GC roots through native
	// submission. WinLDAP copies search input; no Go buffer is retained afterward.
	runtime.KeepAlive(pointers)
	runtime.KeepAlive(controls)
	if status != 0 {
		// Submission failure may leave an uncertain request with no usable ID.
		// Retire the connection instead of replaying or leaving native work owned
		// by a client whose caller has already observed failure.
		return nil, errors.Join(
			InternalLdapStatus("ldap_search_extW", status),
			context.Cause(ctx),
			s.InternalClose(),
		)
	}
	return s.InternalWaitRootDSERead(ctx, messageID, read)
}

func (s *InternalLdapSession) InternalWaitRootDSE(
	ctx context.Context,
	messageID uint32,
) (map[string][][]byte, error) {
	return s.InternalWaitRootDSERead(ctx, messageID, s.InternalReadMessage)
}

func (s *InternalLdapSession) InternalWaitRootDSERead(
	ctx context.Context,
	messageID uint32,
	read func(*ldap.LDAPMessage) (map[string][][]byte, error),
) (map[string][][]byte, error) {
	for {
		wait, err := InternalRemainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return nil, s.InternalAbandon(messageID, nil, err)
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
		if kind == math.MaxUint32 {
			err := s.InternalSessionError("ldap_result")
			if err == nil {
				err = fmt.Errorf(
					"%w: ldap_result failed without an error",
					admodel.ErrInvalidResult,
				)
			}
			return s.InternalPartialAndAbandonRead(
				messageID,
				message,
				errors.Join(err, context.Cause(ctx)),
				read,
			)
		}
		if kind == 0 && message == nil {
			continue
		}
		if message == nil ||
			(kind != uint32(ldap.LDAP_RES_SEARCH_ENTRY) && kind != uint32(ldap.LDAP_RES_SEARCH_RESULT)) {
			return s.InternalPartialAndAbandonRead(
				messageID,
				message,
				fmt.Errorf("%w: unexpected search message", admodel.ErrInvalidResult),
				read,
			)
		}
		attributes, err := read(message)
		return attributes, errors.Join(err, context.Cause(ctx))
	}
}

func (s *InternalLdapSession) InternalPartialAndAbandonRead(
	messageID uint32,
	message *ldap.LDAPMessage,
	cause error,
	read func(*ldap.LDAPMessage) (map[string][][]byte, error),
) (map[string][][]byte, error) {
	var attributes map[string][][]byte
	if message != nil {
		var readErr error
		attributes, readErr = read(message)
		cause = errors.Join(cause, readErr)
	}
	return attributes, s.InternalAbandon(messageID, nil, cause)
}

func (s *InternalLdapSession) InternalAbandon(
	messageID uint32,
	message *ldap.LDAPMessage,
	cause error,
) error {
	if message != nil {
		cause = errors.Join(
			cause,
			InternalLdapStatus("ldap_msgfree", s.InternalApi.InternalMessageFree(message)),
		)
	}
	status := s.InternalApi.InternalAbandon(s.InternalHandle, messageID)
	if status != 0 {
		return errors.Join(cause, InternalLdapStatus("ldap_abandon", status), s.InternalClose())
	}
	// Successful abandon destroys the message ID. Never attempt to drain it.
	return cause
}

func (s *InternalLdapSession) InternalReadMessage(
	message *ldap.LDAPMessage,
) (attributes map[string][][]byte, err error) {
	return s.InternalReadMessageAttributes(message, s.InternalReadAttributes)
}

func (s *InternalLdapSession) InternalReadMessageAttributes(
	message *ldap.LDAPMessage,
	read func(*ldap.LDAPMessage) (map[string][][]byte, error),
) (attributes map[string][][]byte, err error) {
	defer func() {
		err = errors.Join(
			err,
			InternalLdapStatus("ldap_msgfree", s.InternalApi.InternalMessageFree(message)),
		)
	}()
	err = s.InternalParseResponse(message, "LDAP base-object read")
	count := s.InternalApi.InternalCountEntries(s.InternalHandle, message)
	if count == math.MaxUint32 {
		countErr := s.InternalSessionError("ldap_count_entries")
		if countErr == nil {
			countErr = fmt.Errorf(
				"%w: ldap_count_entries failed without an error",
				admodel.ErrInvalidResult,
			)
		}
		return nil, errors.Join(err, countErr)
	}
	if count != 1 {
		if count == 0 && err != nil {
			return nil, err
		}
		return nil, errors.Join(
			err,
			fmt.Errorf(
				"%w: base-object read returned %d entries, expected one",
				admodel.ErrInvalidResult,
				count,
			),
		)
	}
	entry := s.InternalApi.InternalFirstEntry(s.InternalHandle, message)
	if entry == nil {
		return nil, errors.Join(
			err,
			s.InternalSessionError("ldap_first_entry"),
			admodel.ErrInvalidResult,
		)
	}
	attributes, attributeErr := read(entry)
	return attributes, errors.Join(err, attributeErr)
}

func (s *InternalLdapSession) InternalParseResponse(
	message *ldap.LDAPMessage,
	operation string,
) error {
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
	serverError := &admodel.LDAPError{Operation: operation, Code: code}
	if matchedDN != nil {
		defer s.InternalApi.InternalMemoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.InternalApi.InternalMemoryFree(diagnostic)
	}
	if status != 0 {
		// Failure outputs may own storage, but none of their contents are valid.
		return &admodel.LDAPError{Operation: "ldap_parse_resultW", Code: status}
	}
	var matchedErr, diagnosticErr, err error
	serverError.MatchedDN, matchedErr = InternalCopyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = InternalCopyLDAPText(diagnostic)
	if code != 0 {
		err = serverError
	}
	return errors.Join(err, matchedErr, diagnosticErr)
}

func (s *InternalLdapSession) InternalReadAttributes(
	entry *ldap.LDAPMessage,
) (map[string][][]byte, error) {
	return s.InternalReadRawAttributes(entry, false)
}

func (s *InternalLdapSession) InternalReadRawAttributes(
	entry *ldap.LDAPMessage,
	preserveRanges bool,
) (map[string][][]byte, error) {
	return s.InternalReadAttributeProjection(entry, preserveRanges, false)
}

// Internal range consumers assemble and validate the entire value sequence.
// Public RootDSE/Search still reject or mark ranged responses as incomplete.
func (s *InternalLdapSession) InternalReadAttributeProjection(
	entry *ldap.LDAPMessage,
	preserveRanges, rangeConsumer bool,
) (map[string][][]byte, error) {
	// WinLDAP's attribute cursor is tied to the OS thread that creates it.
	// Keep enumeration, value reads, the error query, and cursor cleanup together.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attributes := make(map[string][][]byte)
	var incomplete error
	var cursor *ldap.BerElement
	name := s.InternalApi.InternalFirstAttribute(s.InternalHandle, entry, &cursor)
	defer func() {
		if cursor != nil {
			s.InternalApi.InternalBerFree(cursor, 0)
		}
	}()
	if name != nil && cursor == nil {
		s.InternalApi.InternalMemoryFree(name)
		return attributes, fmt.Errorf(
			"%w: attribute enumeration returned no cursor",
			admodel.ErrInvalidResult,
		)
	}
	for name != nil {
		text, textErr := InternalCopyLDAPText(name)
		s.InternalApi.InternalMemoryFree(name)
		if textErr != nil {
			return attributes, textErr
		}
		key := strings.ToLower(text)
		if strings.Contains(key, ";range=") {
			if !preserveRanges {
				return attributes, fmt.Errorf(
					"%w: ranged base-object attribute",
					admodel.ErrIncompleteResult,
				)
			}
			if !rangeConsumer {
				incomplete = fmt.Errorf(
					"%w: ranged attribute values require additional retrieval",
					admodel.ErrIncompleteResult,
				)
			}
		}
		if !admodel.InternalAttributeDescription.MatchString(text) &&
			(!preserveRanges || !InternalValidRangedAttribute(text)) {
			return attributes, fmt.Errorf(
				"%w: malformed attribute description",
				admodel.ErrInvalidResult,
			)
		}
		if _, found := attributes[key]; found {
			return attributes, fmt.Errorf(
				"%w: duplicate attribute description",
				admodel.ErrInvalidResult,
			)
		}
		values, err := s.InternalReadValues(entry, text)
		attributes[key] = values
		if err != nil {
			return attributes, err
		}
		name = s.InternalApi.InternalNextAttribute(s.InternalHandle, entry, cursor)
	}
	return attributes, errors.Join(incomplete, s.InternalSessionError("LDAP attribute enumeration"))
}

func (s *InternalLdapSession) InternalReadValues(
	entry *ldap.LDAPMessage,
	attribute string,
) (values [][]byte, err error) {
	native := s.InternalApi.InternalValues(s.InternalHandle, entry, attribute)
	if native == nil {
		return nil, s.InternalSessionError("ldap_get_values_lenW")
	}
	defer func() {
		err = errors.Join(
			err,
			InternalLdapStatus("ldap_value_free_len", s.InternalApi.InternalValuesFree(native)),
		)
	}()
	count := s.InternalApi.InternalCountValues(native)
	values = make([][]byte, 0, count)
	for _, value := range unsafe.Slice(native, int(count)) {
		if value == nil || (value.Bv_len > 0 && value.Bv_val == nil) {
			return values, fmt.Errorf(
				"%w: inconsistent binary value pointer",
				admodel.ErrInvalidResult,
			)
		}
		copy := make([]byte, int(value.Bv_len))
		if value.Bv_len > 0 {
			InternalCopyFromNative(copy, value.Bv_val)
		}
		values = append(values, copy)
	}
	return values, nil
}

func InternalCopyFromNative(destination []byte, source foundation.PSTR) {
	copy(destination, unsafe.Slice((*byte)(unsafe.Pointer(source)), len(destination)))
}
