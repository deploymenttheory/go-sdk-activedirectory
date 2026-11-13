//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func (s *ldapSession) baseObject(ctx context.Context, base string, attributes []string) (map[string][][]byte, error) {
	return s.baseObjectRead(ctx, base, attributes, s.readMessage)
}

func (s *ldapSession) rangedBaseObject(ctx context.Context, base string, attributes []string) (map[string][][]byte, error) {
	return s.baseObjectRead(ctx, base, attributes, func(message *ldap.LDAPMessage) (map[string][][]byte, error) {
		return s.readMessageAttributes(message, func(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
			return s.readAttributeProjection(entry, true, true)
		})
	})
}

func (s *ldapSession) baseObjectRead(ctx context.Context, base string, attributes []string, read func(*ldap.LDAPMessage) (map[string][][]byte, error)) (map[string][][]byte, error) {
	return s.baseObjectReadControls(ctx, base, attributes, nil, read)
}

func (s *ldapSession) baseObjectReadControls(ctx context.Context, base string, attributes []string, controls []*ldap.LDAPControlW, read func(*ldap.LDAPMessage) (map[string][][]byte, error)) (map[string][][]byte, error) {
	if s.handle == nil {
		return nil, ErrClosed
	}
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return nil, err
	}
	if err := s.setTimeouts(wait); err != nil {
		return nil, err
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
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
	status := s.api.search(s.handle, &base, ldap.LDAP_SCOPE_BASE, "(objectClass=*)", &pointers[0], 0, serverControls, nil, secondsCeiling(wait), 0, &messageID)
	// The pointer array and every string remain typed GC roots through native
	// submission. WinLDAP copies search input; no Go buffer is retained afterward.
	runtime.KeepAlive(pointers)
	runtime.KeepAlive(controls)
	if status != 0 {
		// Submission failure may leave an uncertain request with no usable ID.
		// Retire the connection instead of replaying or leaving native work owned
		// by a client whose caller has already observed failure.
		return nil, errors.Join(ldapStatus("ldap_search_extW", status), context.Cause(ctx), s.close())
	}
	return s.waitRootDSERead(ctx, messageID, read)
}

func (s *ldapSession) waitRootDSE(ctx context.Context, messageID uint32) (map[string][][]byte, error) {
	return s.waitRootDSERead(ctx, messageID, s.readMessage)
}

func (s *ldapSession) waitRootDSERead(ctx context.Context, messageID uint32, read func(*ldap.LDAPMessage) (map[string][][]byte, error)) (map[string][][]byte, error) {
	for {
		wait, err := remainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return nil, s.abandon(messageID, nil, err)
		}
		timeout := nativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.api.result(s.handle, messageID, ldap.LDAP_MSG_ALL, &timeout, &message)
		if kind == math.MaxUint32 {
			err := s.sessionError("ldap_result")
			if err == nil {
				err = fmt.Errorf("%w: ldap_result failed without an error", ErrInvalidResult)
			}
			return s.partialAndAbandonRead(messageID, message, errors.Join(err, context.Cause(ctx)), read)
		}
		if kind == 0 && message == nil {
			continue
		}
		if message == nil || (kind != uint32(ldap.LDAP_RES_SEARCH_ENTRY) && kind != uint32(ldap.LDAP_RES_SEARCH_RESULT)) {
			return s.partialAndAbandonRead(messageID, message, fmt.Errorf("%w: unexpected search message", ErrInvalidResult), read)
		}
		attributes, err := read(message)
		return attributes, errors.Join(err, context.Cause(ctx))
	}
}

func (s *ldapSession) partialAndAbandonRead(messageID uint32, message *ldap.LDAPMessage, cause error, read func(*ldap.LDAPMessage) (map[string][][]byte, error)) (map[string][][]byte, error) {
	var attributes map[string][][]byte
	if message != nil {
		var readErr error
		attributes, readErr = read(message)
		cause = errors.Join(cause, readErr)
	}
	return attributes, s.abandon(messageID, nil, cause)
}

func (s *ldapSession) abandon(messageID uint32, message *ldap.LDAPMessage, cause error) error {
	if message != nil {
		cause = errors.Join(cause, ldapStatus("ldap_msgfree", s.api.messageFree(message)))
	}
	status := s.api.abandon(s.handle, messageID)
	if status != 0 {
		return errors.Join(cause, ldapStatus("ldap_abandon", status), s.close())
	}
	// Successful abandon destroys the message ID. Never attempt to drain it.
	return cause
}

func (s *ldapSession) readMessage(message *ldap.LDAPMessage) (attributes map[string][][]byte, err error) {
	return s.readMessageAttributes(message, s.readAttributes)
}

func (s *ldapSession) readMessageAttributes(message *ldap.LDAPMessage, read func(*ldap.LDAPMessage) (map[string][][]byte, error)) (attributes map[string][][]byte, err error) {
	defer func() { err = errors.Join(err, ldapStatus("ldap_msgfree", s.api.messageFree(message))) }()
	err = s.parseResponse(message, "LDAP base-object read")
	count := s.api.countEntries(s.handle, message)
	if count == math.MaxUint32 {
		countErr := s.sessionError("ldap_count_entries")
		if countErr == nil {
			countErr = fmt.Errorf("%w: ldap_count_entries failed without an error", ErrInvalidResult)
		}
		return nil, errors.Join(err, countErr)
	}
	if count != 1 {
		if count == 0 && err != nil {
			return nil, err
		}
		return nil, errors.Join(err, fmt.Errorf("%w: base-object read returned %d entries, expected one", ErrInvalidResult, count))
	}
	entry := s.api.firstEntry(s.handle, message)
	if entry == nil {
		return nil, errors.Join(err, s.sessionError("ldap_first_entry"), ErrInvalidResult)
	}
	attributes, attributeErr := read(entry)
	return attributes, errors.Join(err, attributeErr)
}

func (s *ldapSession) parseResponse(message *ldap.LDAPMessage, operation string) error {
	var code uint32
	var matchedDN, diagnostic foundation.PWSTR
	status := s.api.parseResult(s.handle, message, &code, &matchedDN, &diagnostic, nil, nil, 0)
	serverError := &LDAPError{Operation: operation, Code: code}
	if matchedDN != nil {
		defer s.api.memoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.api.memoryFree(diagnostic)
	}
	if status != 0 {
		// Failure outputs may own storage, but none of their contents are valid.
		return &LDAPError{Operation: "ldap_parse_resultW", Code: status}
	}
	var matchedErr, diagnosticErr, err error
	serverError.MatchedDN, matchedErr = copyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = copyLDAPText(diagnostic)
	if code != 0 {
		err = serverError
	}
	return errors.Join(err, matchedErr, diagnosticErr)
}

func (s *ldapSession) readAttributes(entry *ldap.LDAPMessage) (map[string][][]byte, error) {
	return s.readRawAttributes(entry, false)
}

func (s *ldapSession) readRawAttributes(entry *ldap.LDAPMessage, preserveRanges bool) (map[string][][]byte, error) {
	return s.readAttributeProjection(entry, preserveRanges, false)
}

// Internal range consumers assemble and validate the entire value sequence.
// Public RootDSE/Search still reject or mark ranged responses as incomplete.
func (s *ldapSession) readAttributeProjection(entry *ldap.LDAPMessage, preserveRanges, rangeConsumer bool) (map[string][][]byte, error) {
	// WinLDAP's attribute cursor is tied to the OS thread that creates it.
	// Keep enumeration, value reads, the error query, and cursor cleanup together.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	attributes := make(map[string][][]byte)
	var incomplete error
	var cursor *ldap.BerElement
	name := s.api.firstAttribute(s.handle, entry, &cursor)
	defer func() {
		if cursor != nil {
			s.api.berFree(cursor, 0)
		}
	}()
	if name != nil && cursor == nil {
		s.api.memoryFree(name)
		return attributes, fmt.Errorf("%w: attribute enumeration returned no cursor", ErrInvalidResult)
	}
	for name != nil {
		text, textErr := copyLDAPText(name)
		s.api.memoryFree(name)
		if textErr != nil {
			return attributes, textErr
		}
		key := strings.ToLower(text)
		if strings.Contains(key, ";range=") {
			if !preserveRanges {
				return attributes, fmt.Errorf("%w: ranged base-object attribute", ErrIncompleteResult)
			}
			if !rangeConsumer {
				incomplete = fmt.Errorf("%w: ranged attribute values require additional retrieval", ErrIncompleteResult)
			}
		}
		if !attributeDescription.MatchString(text) && !(preserveRanges && validRangedAttribute(text)) {
			return attributes, fmt.Errorf("%w: malformed attribute description", ErrInvalidResult)
		}
		if _, found := attributes[key]; found {
			return attributes, fmt.Errorf("%w: duplicate attribute description", ErrInvalidResult)
		}
		values, err := s.readValues(entry, text)
		attributes[key] = values
		if err != nil {
			return attributes, err
		}
		name = s.api.nextAttribute(s.handle, entry, cursor)
	}
	return attributes, errors.Join(incomplete, s.sessionError("LDAP attribute enumeration"))
}

func (s *ldapSession) readValues(entry *ldap.LDAPMessage, attribute string) (values [][]byte, err error) {
	native := s.api.values(s.handle, entry, attribute)
	if native == nil {
		return nil, s.sessionError("ldap_get_values_lenW")
	}
	defer func() { err = errors.Join(err, ldapStatus("ldap_value_free_len", s.api.valuesFree(native))) }()
	count := s.api.countValues(native)
	values = make([][]byte, 0, count)
	for _, value := range unsafe.Slice(native, int(count)) {
		if value == nil || (value.Bv_len > 0 && value.Bv_val == nil) {
			return values, fmt.Errorf("%w: inconsistent binary value pointer", ErrInvalidResult)
		}
		copy := make([]byte, int(value.Bv_len))
		if value.Bv_len > 0 {
			copyFromNative(copy, value.Bv_val)
		}
		values = append(values, copy)
	}
	return values, nil
}

func copyFromNative(destination []byte, source foundation.PSTR) {
	copy(destination, unsafe.Slice((*byte)(unsafe.Pointer(source)), len(destination)))
}

func validRangedAttribute(name string) bool {
	base, tail, ok := strings.Cut(strings.ToLower(name), ";range=")
	if !ok || !attributeDescription.MatchString(base) {
		return false
	}
	startText, endText, ok := strings.Cut(tail, "-")
	if !ok {
		return false
	}
	start, err := strconv.ParseUint(startText, 10, 32)
	if err != nil {
		return false
	}
	if endText == "*" {
		return true
	}
	end, err := strconv.ParseUint(endText, 10, 32)
	return err == nil && end >= start
}
