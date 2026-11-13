//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

type ldapSearch struct {
	session       *ldapSession
	options       SearchOptions
	attributes    []*uint16
	pageTimeLimit uint32
	cookie        *ldap.LDAP_BERVAL
	activeID      *uint32
	retire        bool
	closed        bool
	closeErr      error
	controls      []ldapWriteControl
}

func (s *ldapSession) startSearch(ctx context.Context, options SearchOptions) (searchCursor, error) {
	return s.startSearchControls(ctx, options, nil)
}

func (s *ldapSession) startSearchControls(ctx context.Context, options SearchOptions, controls []ldapWriteControl) (searchCursor, error) {
	if s.handle == nil {
		return nil, ErrClosed
	}
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	controls = slices.Clone(controls)
	for i := range controls {
		if !validLDAPWriteOID(controls[i].oid) || controls[i].oid == "1.2.840.113556.1.4.319" || uint64(len(controls[i].value)) > math.MaxUint32 {
			return nil, ErrInvalidSearch
		}
		controls[i].value = slices.Clone(controls[i].value)
	}
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return nil, err
	}
	for _, proc := range []*win32.Proc{ldap.Procs.Ldap_create_page_controlW, ldap.Procs.Ldap_parse_page_controlW,
		ldap.Procs.Ldap_control_freeW, ldap.Procs.Ldap_controls_freeW, ldap.Procs.Ber_bvfree,
		ldap.Procs.Ldap_next_entry, ldap.Procs.Ldap_get_dnW, ldap.Procs.Ldap_count_references} {
		if err := s.api.find(proc); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	attributes := make([]*uint16, len(options.Properties)+1)
	for i, name := range options.Properties {
		attributes[i] = win32.UTF16Ptr(name)
	}
	return &ldapSearch{session: s, options: options, attributes: attributes, pageTimeLimit: secondsCeiling(wait), controls: controls}, nil
}

func (p *ldapSearch) submit(ctx context.Context, size uint32) (err error) {
	s := p.session
	wait, err := remainingWait(ctx, s.timeout)
	if err != nil {
		return err
	}
	if err := s.setTimeouts(wait); err != nil {
		return err
	}
	var control *ldap.LDAPControlW
	status := s.api.createPageControl(s.handle, size, p.cookie, 1, &control)
	if control != nil {
		defer func() { err = errors.Join(err, ldapStatus("ldap_control_freeW", s.api.controlFree(control))) }()
	}
	if status != 0 {
		return ldapStatus("ldap_create_page_controlW", status)
	}
	if control == nil {
		return fmt.Errorf("%w: missing page control", ErrInvalidResult)
	}
	inputs := makeLDAPWriteInputs(ldapWriteRequest{controls: p.controls})
	controls := []*ldap.LDAPControlW{control}
	if len(inputs.controlPointers) != 0 {
		controls = append(controls, inputs.controlPointers[:len(inputs.controlPointers)-1]...)
	}
	controls = append(controls, nil)
	var id uint32
	// RFC2696 keeps every search field stable except page size/cookie/message ID.
	// The polling context enforces the shrinking deadline independently.
	status = s.api.search(s.handle, &p.options.Base, uint32(p.options.Scope), p.options.Filter, &p.attributes[0], 0, &controls[0], nil, p.pageTimeLimit, 0, &id)
	runtime.KeepAlive(controls)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(p.controls)
	runtime.KeepAlive(p.attributes)
	if status != 0 {
		p.retire = true
		return ldapStatus("ldap_search_extW", status)
	}
	p.activeID = &id
	return nil
}

func (p *ldapSearch) next(ctx context.Context, size uint32) ([]Object, bool, error) {
	if err := p.submit(ctx, size); err != nil {
		return nil, false, err
	}
	return p.wait(ctx)
}

func (p *ldapSearch) wait(ctx context.Context) ([]Object, bool, error) {
	s := p.session
	for {
		wait, err := remainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return nil, false, err
		}
		timeout := nativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.api.result(s.handle, *p.activeID, ldap.LDAP_MSG_ALL, &timeout, &message)
		if kind == 0 && message == nil {
			continue
		}
		var resultErr error
		if kind == math.MaxUint32 {
			resultErr = s.sessionError("ldap_result")
			if resultErr == nil {
				resultErr = fmt.Errorf("%w: ldap_result failed without an error", ErrInvalidResult)
			}
		} else if message == nil || (kind != uint32(ldap.LDAP_RES_SEARCH_ENTRY) && kind != uint32(ldap.LDAP_RES_SEARCH_RESULT) && kind != uint32(ldap.LDAP_RES_REFERRAL)) {
			resultErr = fmt.Errorf("%w: unexpected search message", ErrInvalidResult)
		}
		if message == nil {
			return nil, false, errors.Join(resultErr, context.Cause(ctx))
		}
		objects, parsed, done, readErr := p.readPage(message)
		if resultErr == nil && parsed {
			p.activeID = nil
		}
		return objects, done, errors.Join(resultErr, readErr, context.Cause(ctx))
	}
}

func (p *ldapSearch) readPage(message *ldap.LDAPMessage) (objects []Object, parsed, done bool, err error) {
	s := p.session
	defer func() { err = errors.Join(err, ldapStatus("ldap_msgfree", s.api.messageFree(message))) }()
	var code uint32
	var matchedDN, diagnostic foundation.PWSTR
	var controls **ldap.LDAPControlW
	status := s.api.parseResult(s.handle, message, &code, &matchedDN, &diagnostic, nil, &controls, 0)
	if controls != nil {
		defer func() { err = errors.Join(err, ldapStatus("ldap_controls_freeW", s.api.controlsFree(controls))) }()
	}
	serverError := &LDAPError{Operation: "Search", Code: code}
	if matchedDN != nil {
		defer s.api.memoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.api.memoryFree(diagnostic)
	}
	if status != 0 {
		serverError.Operation = "ldap_parse_resultW"
		serverError.Code = status
		p.retire = true
		// A failed parser may supply owned allocations, not usable outputs.
		// Deferred frees release them without dereferencing their contents.
		return nil, false, false, serverError
	}
	parsed = true
	var matchedErr, diagnosticErr error
	serverError.MatchedDN, matchedErr = copyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = copyLDAPText(diagnostic)
	if code != 0 {
		err = serverError
	}
	err = errors.Join(err, matchedErr, diagnosticErr)
	if controls != nil {
		var estimate uint32
		var cookie *ldap.LDAP_BERVAL
		pageStatus := s.api.parsePageControl(s.handle, controls, &estimate, &cookie)
		if p.cookie != nil {
			s.api.cookieFree(p.cookie)
		}
		p.cookie = cookie
		if pageStatus != 0 {
			err = errors.Join(err, ldapStatus("ldap_parse_page_controlW", pageStatus))
			p.retire = true
		} else if cookie == nil || (cookie.Bv_len > 0 && cookie.Bv_val == nil) {
			err = errors.Join(err, fmt.Errorf("%w: missing or invalid page cookie", ErrInvalidResult))
			p.retire = true
		} else {
			done = cookie.Bv_len == 0
		}
	} else {
		if code != 0 {
			// A terminal LDAP failure closes this search sequence (RFC2696).
			// No paging response is required to report e.g. noSuchObject, and
			// this alone does not make the authenticated connection uncertain.
			if p.cookie != nil {
				s.api.cookieFree(p.cookie)
				p.cookie = nil
			}
		} else {
			p.retire = true
			err = errors.Join(err, fmt.Errorf("%w: server omitted the critical paging response", ErrIncompleteResult))
		}
	}
	if references := s.api.countReferences(s.handle, message); references != 0 {
		if references == math.MaxUint32 {
			err = errors.Join(err, s.sessionError("ldap_count_references"), ErrInvalidResult)
		} else {
			err = errors.Join(err, fmt.Errorf("%w: search references require explicit retrieval on another endpoint", ErrIncompleteResult))
		}
	}
	count := s.api.countEntries(s.handle, message)
	if count == math.MaxUint32 {
		return nil, parsed, done, errors.Join(err, s.sessionError("ldap_count_entries"), ErrInvalidResult)
	}
	entry := s.api.firstEntry(s.handle, message)
	for i := uint32(0); i < count; i++ {
		if entry == nil {
			return objects, parsed, done, errors.Join(err, s.sessionError("LDAP entry enumeration"), ErrInvalidResult)
		}
		object := Object{}
		dn := s.api.getDN(s.handle, entry)
		if dn == nil {
			return objects, parsed, done, errors.Join(err, s.sessionError("ldap_get_dnW"), ErrInvalidResult)
		}
		var dnErr error
		object.DistinguishedName, dnErr = copyLDAPText(dn)
		s.api.memoryFree(dn)
		if dnErr != nil {
			return objects, parsed, done, errors.Join(err, dnErr)
		}
		var attributeErr error
		object.Attributes, attributeErr = s.readRawAttributes(entry, true)
		objects = append(objects, object)
		err = errors.Join(err, attributeErr)
		entry = s.api.nextEntry(s.handle, entry)
	}
	if entry != nil {
		err = errors.Join(err, fmt.Errorf("%w: entry count mismatch", ErrInvalidResult))
	}
	return objects, parsed, done, err
}

func (p *ldapSearch) close() error {
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	s := p.session
	if p.activeID != nil {
		// An outstanding request may have advanced the cookie. Abandon it and
		// retire the connection; never reuse an uncertain server cursor.
		p.closeErr = ldapStatus("ldap_abandon", s.api.abandon(s.handle, *p.activeID))
		p.activeID = nil
		p.retire = true
	}
	if !p.retire && p.cookie != nil && p.cookie.Bv_len > 0 {
		// RFC2696 releases a cursor with the last cookie and a zero page size.
		// Use our bounded async wait: ldap_search_abandon_page performs an
		// unbounded synchronous wait on this path on tested Windows builds.
		ctx, cancel := context.WithTimeout(context.Background(), min(s.timeout, 100*time.Millisecond))
		err := p.submit(ctx, 0)
		if err == nil {
			var objects []Object
			var done bool
			objects, done, err = p.wait(ctx)
			if err == nil && (!done || len(objects) != 0) {
				err = fmt.Errorf("%w: server did not release paging cookie", ErrInvalidResult)
			}
		}
		cancel()
		p.closeErr = errors.Join(p.closeErr, err)
		if p.activeID != nil {
			p.closeErr = errors.Join(p.closeErr, ldapStatus("ldap_abandon", s.api.abandon(s.handle, *p.activeID)))
			p.activeID = nil
		}
		if err != nil {
			p.retire = true
		}
	}
	if p.cookie != nil {
		s.api.cookieFree(p.cookie)
		p.cookie = nil
	}
	p.attributes = nil
	p.controls = nil
	if p.retire {
		p.closeErr = errors.Join(p.closeErr, s.close())
	}
	return p.closeErr
}
