package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableControl struct {
	admodel.InternalLdapWriteControl
}

func (c portableControl) GetControlType() string { return c.InternalOid }
func (c portableControl) String() string         { return "LDAP control " + c.InternalOid }
func (c portableControl) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.InternalOid, "OID"))
	if c.InternalCritical {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Critical"))
	}
	if c.InternalValue != nil {
		value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Value")
		value.Data.Write(c.InternalValue)
		packet.AppendChild(value)
	}
	return packet
}

func internalPortableControls(input []admodel.InternalLdapWriteControl) []ldap.Control {
	controls := make([]ldap.Control, len(input))
	for i, control := range input {
		control.InternalValue = slices.Clone(control.InternalValue)
		controls[i] = portableControl{control}
	}
	return controls
}

func internalPortablePaging(size uint32, cookie []byte) ldap.Control {
	value := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	value.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(size), ""))
	opaque := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "")
	opaque.Data.Write(cookie)
	value.AppendChild(opaque)
	return portableControl{admodel.InternalLdapWriteControl{InternalOid: ldap.ControlTypePaging, InternalCritical: true, InternalValue: value.Bytes()}}
}

// InternalPortableSearch owns one RFC 2696 cursor and its stable query/controls.
// It copies opaque cookies and explicitly releases a caller-limited sequence.
type InternalPortableSearch struct {
	session  *InternalPortableSession
	ctx      context.Context
	options  admodel.SearchOptions
	controls []ldap.Control
	cookie   []byte
	retire   bool
	closed   bool
	closeErr error
}

func (s *InternalPortableSession) InternalStartSearch(ctx context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
	return s.InternalStartSearchControls(ctx, options, nil)
}

func (s *InternalPortableSession) InternalStartSearchControls(
	ctx context.Context,
	options admodel.SearchOptions,
	controls []admodel.InternalLdapWriteControl,
) (admodel.InternalSearchCursor, error) {
	if s.closed.Load() {
		return nil, admodel.ErrClosed
	}
	if cause := InternalConnectionContextCause(ctx); cause != nil {
		return nil, cause
	}
	options, err := admodel.InternalPortableSearchOptionsNormalized(options)
	if err != nil {
		return nil, err
	}
	if _, err := ldap.CompileFilter(options.Filter); err != nil {
		return nil, admodel.ErrInvalidSearch
	}
	for _, control := range controls {
		if !InternalValidLDAPWriteOID(control.InternalOid) || control.InternalOid == ldap.ControlTypePaging {
			return nil, admodel.ErrInvalidSearch
		}
	}
	options.Properties = slices.Clone(options.Properties)
	return &InternalPortableSearch{session: s, ctx: ctx, options: options, controls: internalPortableControls(controls)}, nil
}

func (p *InternalPortableSearch) InternalNext(ctx context.Context, size uint32) ([]admodel.Object, bool, error) {
	if p.closed || p.session.closed.Load() {
		return nil, false, admodel.ErrClosed
	}
	return p.page(ctx, size)
}

func (p *InternalPortableSearch) page(ctx context.Context, size uint32) ([]admodel.Object, bool, error) {
	controls := append(slices.Clone(p.controls), internalPortablePaging(size, p.cookie))
	var response *ldap.SearchResult
	err := p.session.invoke(ctx, "search", func() error {
		var readErr error
		response, readErr = p.session.ldap.Search(
			ldap.NewSearchRequest(p.options.Base, int(p.options.Scope), ldap.NeverDerefAliases, 0, 0, false, p.options.Filter, p.options.Properties, controls),
		)
		return readErr
	})
	if response == nil {
		p.retire = true
		return nil, false, errors.Join(err, admodel.ErrIncompleteResult)
	}
	objects := make([]admodel.Object, 0, len(response.Entries))
	for _, entry := range response.Entries {
		object, decodeErr := internalPortableObject(entry, true, false)
		objects = append(objects, object)
		err = errors.Join(err, decodeErr)
		if errors.Is(decodeErr, admodel.ErrInvalidResult) {
			p.retire = true
		}
	}
	if len(response.Referrals) > 0 {
		err = errors.Join(err, admodel.ErrSearchReferences)
	}
	var paging *ldap.ControlPaging
	for _, control := range response.Controls {
		if candidate, ok := control.(*ldap.ControlPaging); ok {
			if paging != nil {
				p.retire = true
				err = errors.Join(err, admodel.ErrInvalidResult)
			}
			paging = candidate
		}
	}
	if paging == nil {
		var refusal *admodel.LDAPError
		if errors.As(err, &refusal) {
			// A terminal LDAP refusal ends this sequence without requiring a
			// paging response. Do not replay or release an expired cookie.
			clear(p.cookie)
			p.cookie = nil
			return objects, true, err
		}
		p.retire = true
		return objects, false, errors.Join(err, fmt.Errorf("%w: server omitted critical paging response", admodel.ErrIncompleteResult))
	}
	p.cookie = slices.Clone(paging.Cookie)
	done := len(p.cookie) == 0
	if err != nil && p.session.closed.Load() {
		p.retire = true
	}
	return objects, done, err
}

func (p *InternalPortableSearch) InternalClose() error {
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	if p.retire || p.session.closed.Load() {
		p.closeErr = p.session.InternalClose()
		return p.closeErr
	}
	if len(p.cookie) > 0 {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(p.ctx), min(p.session.timeout, 100*time.Millisecond))
		objects, done, err := p.page(ctx, 0)
		cancel()
		if err == nil && (!done || len(objects) != 0) {
			err = admodel.ErrInvalidResult
		}
		p.closeErr = err
		if err != nil {
			p.closeErr = errors.Join(err, p.session.InternalClose())
		}
	}
	clear(p.cookie)
	p.cookie = nil
	p.controls = nil
	return p.closeErr
}
