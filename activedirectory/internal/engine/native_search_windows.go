//go:build windows && (amd64 || arm64)

package engine

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
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalLdapSearch struct {
	InternalSession       *InternalLdapSession
	InternalOptions       admodel.SearchOptions
	InternalAttributes    []*uint16
	InternalPageTimeLimit uint32
	InternalCookie        *ldap.LDAP_BERVAL
	InternalActiveID      *uint32
	InternalRetire        bool
	InternalClosed        bool
	InternalCloseErr      error
	InternalControls      []admodel.InternalLdapWriteControl
}

func (s *InternalLdapSession) InternalStartSearch(
	ctx context.Context,
	options admodel.SearchOptions,
) (admodel.InternalSearchCursor, error) {
	return s.InternalStartSearchControls(ctx, options, nil)
}

func (s *InternalLdapSession) InternalStartSearchControls(
	ctx context.Context,
	options admodel.SearchOptions,
	controls []admodel.InternalLdapWriteControl,
) (admodel.InternalSearchCursor, error) {
	if s.InternalHandle == nil {
		return nil, admodel.ErrClosed
	}
	if err := context.Cause(ctx); err != nil {
		return nil, fmt.Errorf("LDAP search cancelled: %w", err)
	}
	controls = slices.Clone(controls)
	for i := range controls {
		if !InternalValidLDAPWriteOID(controls[i].InternalOid) ||
			controls[i].InternalOid == "1.2.840.113556.1.4.319" ||
			uint64(len(controls[i].InternalValue)) > math.MaxUint32 {
			return nil, admodel.ErrInvalidSearch
		}
		controls[i].InternalValue = slices.Clone(controls[i].InternalValue)
	}
	wait, err := InternalRemainingWait(ctx, s.InternalTimeout)
	if err != nil {
		return nil, err
	}
	for _, proc := range []*win32.Proc{
		ldap.Procs.Ldap_create_page_controlW, ldap.Procs.Ldap_parse_page_controlW,
		ldap.Procs.Ldap_control_freeW, ldap.Procs.Ldap_controls_freeW, ldap.Procs.Ber_bvfree,
		ldap.Procs.Ldap_next_entry, ldap.Procs.Ldap_get_dnW, ldap.Procs.Ldap_count_references,
	} {
		if err := s.InternalApi.InternalFind(proc); err != nil {
			return nil, fmt.Errorf("%w: %w", admodel.ErrUnsupported, err)
		}
	}
	attributes := make([]*uint16, len(options.Properties)+1)
	for i, name := range options.Properties {
		attributes[i] = win32.UTF16Ptr(name)
	}
	return &InternalLdapSearch{
		InternalSession:       s,
		InternalOptions:       options,
		InternalAttributes:    attributes,
		InternalPageTimeLimit: InternalSecondsCeiling(wait),
		InternalControls:      controls,
	}, nil
}

func (p *InternalLdapSearch) InternalSubmit(ctx context.Context, size uint32) (err error) {
	s := p.InternalSession
	wait, err := InternalRemainingWait(ctx, s.InternalTimeout)
	if err != nil {
		return err
	}
	if err := s.InternalSetTimeouts(wait); err != nil {
		return err
	}
	var control *ldap.LDAPControlW
	status := s.InternalApi.InternalCreatePageControl(
		s.InternalHandle,
		size,
		p.InternalCookie,
		1,
		&control,
	)
	if control != nil {
		defer func() {
			err = errors.Join(
				err,
				InternalLdapStatus(
					"ldap_control_freeW",
					s.InternalApi.InternalControlFree(control),
				),
			)
		}()
	}
	if status != 0 {
		return InternalLdapStatus("ldap_create_page_controlW", status)
	}
	if control == nil {
		return fmt.Errorf("%w: missing page control", admodel.ErrInvalidResult)
	}
	inputs, err := InternalMakeLDAPWriteInputs(
		admodel.InternalLdapWriteRequest{InternalControls: p.InternalControls},
	)
	if err != nil {
		return err
	}
	controls := []*ldap.LDAPControlW{control}
	if len(inputs.InternalControlPointers) != 0 {
		controls = append(
			controls,
			inputs.InternalControlPointers[:len(inputs.InternalControlPointers)-1]...)
	}
	controls = append(controls, nil)
	var id uint32
	// RFC2696 keeps every search field stable except page size/cookie/message ID.
	// The polling context enforces the shrinking deadline independently.
	status = s.InternalApi.InternalSearch(
		s.InternalHandle,
		&p.InternalOptions.Base,
		uint32(p.InternalOptions.Scope),
		p.InternalOptions.Filter,
		&p.InternalAttributes[0],
		0,
		&controls[0],
		nil,
		p.InternalPageTimeLimit,
		0,
		&id,
	)
	runtime.KeepAlive(controls)
	runtime.KeepAlive(inputs)
	runtime.KeepAlive(p.InternalControls)
	runtime.KeepAlive(p.InternalAttributes)
	if status != 0 {
		p.InternalRetire = true
		return InternalLdapStatus("ldap_search_extW", status)
	}
	p.InternalActiveID = &id
	return nil
}

func (p *InternalLdapSearch) InternalNext(
	ctx context.Context,
	size uint32,
) ([]admodel.Object, bool, error) {
	if err := p.InternalSubmit(ctx, size); err != nil {
		return nil, false, err
	}
	return p.InternalWait(ctx)
}

func (p *InternalLdapSearch) InternalWait(ctx context.Context) ([]admodel.Object, bool, error) {
	s := p.InternalSession
	for {
		wait, err := InternalRemainingWait(ctx, 50*time.Millisecond)
		if err != nil {
			return nil, false, err
		}
		timeout := InternalNativeTimeval(wait)
		var message *ldap.LDAPMessage
		kind := s.InternalApi.InternalResult(
			s.InternalHandle,
			*p.InternalActiveID,
			ldap.LDAP_MSG_ALL,
			&timeout,
			&message,
		)
		if kind == 0 && message == nil {
			continue
		}
		var resultErr error
		if kind == math.MaxUint32 {
			resultErr = s.InternalSessionError("ldap_result")
			if resultErr == nil {
				resultErr = fmt.Errorf(
					"%w: ldap_result failed without an error",
					admodel.ErrInvalidResult,
				)
			}
		} else if message == nil || (kind != uint32(ldap.LDAP_RES_SEARCH_ENTRY) && kind != uint32(ldap.LDAP_RES_SEARCH_RESULT) && kind != uint32(ldap.LDAP_RES_REFERRAL)) {
			resultErr = fmt.Errorf("%w: unexpected search message", admodel.ErrInvalidResult)
		}
		if message == nil {
			return nil, false, errors.Join(resultErr, context.Cause(ctx))
		}
		objects, parsed, done, readErr := p.InternalReadPage(message)
		if resultErr == nil && parsed {
			p.InternalActiveID = nil
		}
		return objects, done, errors.Join(resultErr, readErr, context.Cause(ctx))
	}
}

func (p *InternalLdapSearch) InternalReadPage(
	message *ldap.LDAPMessage,
) (objects []admodel.Object, parsed, done bool, err error) {
	s := p.InternalSession
	defer func() {
		err = errors.Join(
			err,
			InternalLdapStatus("ldap_msgfree", s.InternalApi.InternalMessageFree(message)),
		)
	}()
	var code uint32
	var matchedDN, diagnostic foundation.PWSTR
	var controls **ldap.LDAPControlW
	status := s.InternalApi.InternalParseResult(
		s.InternalHandle,
		message,
		&code,
		&matchedDN,
		&diagnostic,
		nil,
		&controls,
		0,
	)
	if controls != nil {
		defer func() {
			err = errors.Join(
				err,
				InternalLdapStatus(
					"ldap_controls_freeW",
					s.InternalApi.InternalControlsFree(controls),
				),
			)
		}()
	}
	serverError := &admodel.LDAPError{Operation: "Search", Code: code}
	if matchedDN != nil {
		defer s.InternalApi.InternalMemoryFree(matchedDN)
	}
	if diagnostic != nil {
		defer s.InternalApi.InternalMemoryFree(diagnostic)
	}
	if status != 0 {
		serverError.Operation = "ldap_parse_resultW"
		serverError.Code = status
		p.InternalRetire = true
		// A failed parser may supply owned allocations, not usable outputs.
		// Deferred frees release them without dereferencing their contents.
		return nil, false, false, serverError
	}
	parsed = true
	var matchedErr, diagnosticErr error
	serverError.MatchedDN, matchedErr = InternalCopyLDAPText(matchedDN)
	serverError.Diagnostic, diagnosticErr = InternalCopyLDAPText(diagnostic)
	if code != 0 {
		err = serverError
	}
	err = errors.Join(err, matchedErr, diagnosticErr)
	if controls != nil {
		var estimate uint32
		var cookie *ldap.LDAP_BERVAL
		pageStatus := s.InternalApi.InternalParsePageControl(
			s.InternalHandle,
			controls,
			&estimate,
			&cookie,
		)
		if p.InternalCookie != nil {
			s.InternalApi.InternalCookieFree(p.InternalCookie)
		}
		p.InternalCookie = cookie
		switch {
		case pageStatus != 0:
			err = errors.Join(err, InternalLdapStatus("ldap_parse_page_controlW", pageStatus))
			p.InternalRetire = true
		case cookie == nil || (cookie.Bv_len > 0 && cookie.Bv_val == nil):
			err = errors.Join(
				err,
				fmt.Errorf("%w: missing or invalid page cookie", admodel.ErrInvalidResult),
			)
			p.InternalRetire = true
		default:
			done = cookie.Bv_len == 0
		}
	} else {
		if code != 0 {
			// A terminal LDAP failure closes this search sequence (RFC2696).
			// No paging response is required to report e.g. noSuchObject, and
			// this alone does not make the authenticated connection uncertain.
			if p.InternalCookie != nil {
				s.InternalApi.InternalCookieFree(p.InternalCookie)
				p.InternalCookie = nil
			}
		} else {
			p.InternalRetire = true
			err = errors.Join(
				err,
				fmt.Errorf(
					"%w: server omitted the critical paging response",
					admodel.ErrIncompleteResult,
				),
			)
		}
	}
	if references := s.InternalApi.InternalCountReferences(
		s.InternalHandle,
		message,
	); references != 0 {
		if references == math.MaxUint32 {
			err = errors.Join(
				err,
				s.InternalSessionError("ldap_count_references"),
				admodel.ErrInvalidResult,
			)
		} else {
			err = errors.Join(err, admodel.ErrSearchReferences)
		}
	}
	count := s.InternalApi.InternalCountEntries(s.InternalHandle, message)
	if count == math.MaxUint32 {
		return nil, parsed, done, errors.Join(
			err,
			s.InternalSessionError("ldap_count_entries"),
			admodel.ErrInvalidResult,
		)
	}
	entry := s.InternalApi.InternalFirstEntry(s.InternalHandle, message)
	for i := uint32(0); i < count; i++ {
		if entry == nil {
			return objects, parsed, done, errors.Join(
				err,
				s.InternalSessionError("LDAP entry enumeration"),
				admodel.ErrInvalidResult,
			)
		}
		object := admodel.Object{}
		dn := s.InternalApi.InternalGetDN(s.InternalHandle, entry)
		if dn == nil {
			return objects, parsed, done, errors.Join(
				err,
				s.InternalSessionError("ldap_get_dnW"),
				admodel.ErrInvalidResult,
			)
		}
		var dnErr error
		object.DistinguishedName, dnErr = InternalCopyLDAPText(dn)
		s.InternalApi.InternalMemoryFree(dn)
		if dnErr != nil {
			return objects, parsed, done, errors.Join(err, dnErr)
		}
		var attributeErr error
		object.Attributes, attributeErr = s.InternalReadRawAttributes(entry, true)
		objects = append(objects, object)
		err = errors.Join(err, attributeErr)
		entry = s.InternalApi.InternalNextEntry(s.InternalHandle, entry)
	}
	if entry != nil {
		err = errors.Join(err, fmt.Errorf("%w: entry count mismatch", admodel.ErrInvalidResult))
	}
	return objects, parsed, done, err
}

func (p *InternalLdapSearch) InternalClose() error {
	if p.InternalClosed {
		return p.InternalCloseErr
	}
	p.InternalClosed = true
	s := p.InternalSession
	if p.InternalActiveID != nil {
		// An outstanding request may have advanced the cookie. Abandon it and
		// retire the connection; never reuse an uncertain server cursor.
		p.InternalCloseErr = InternalLdapStatus(
			"ldap_abandon",
			s.InternalApi.InternalAbandon(s.InternalHandle, *p.InternalActiveID),
		)
		p.InternalActiveID = nil
		p.InternalRetire = true
	}
	if !p.InternalRetire && p.InternalCookie != nil && p.InternalCookie.Bv_len > 0 {
		// RFC2696 releases a cursor with the last cookie and a zero page size.
		// Use our bounded async wait: ldap_search_abandon_page performs an
		// unbounded synchronous wait on this path on tested Windows builds.
		ctx, cancel := context.WithTimeout(
			context.Background(),
			min(s.InternalTimeout, 100*time.Millisecond),
		)
		err := p.InternalSubmit(ctx, 0)
		if err == nil {
			var objects []admodel.Object
			var done bool
			objects, done, err = p.InternalWait(ctx)
			if err == nil && (!done || len(objects) != 0) {
				err = fmt.Errorf(
					"%w: server did not release paging cookie",
					admodel.ErrInvalidResult,
				)
			}
		}
		cancel()
		p.InternalCloseErr = errors.Join(p.InternalCloseErr, err)
		if p.InternalActiveID != nil {
			p.InternalCloseErr = errors.Join(
				p.InternalCloseErr,
				InternalLdapStatus(
					"ldap_abandon",
					s.InternalApi.InternalAbandon(s.InternalHandle, *p.InternalActiveID),
				),
			)
			p.InternalActiveID = nil
		}
		if err != nil {
			p.InternalRetire = true
		}
	}
	if p.InternalCookie != nil {
		s.InternalApi.InternalCookieFree(p.InternalCookie)
		p.InternalCookie = nil
	}
	p.InternalAttributes = nil
	p.InternalControls = nil
	if p.InternalRetire {
		p.InternalCloseErr = errors.Join(p.InternalCloseErr, s.InternalClose())
	}
	return p.InternalCloseErr
}
