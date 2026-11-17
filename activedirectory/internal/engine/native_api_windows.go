//go:build windows && (amd64 || arm64)

package engine

import (
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Each session owns its boundary, so failure/lifetime tests never replace
// process-wide callbacks. Types and dispatch come from the pinned bindings.
type InternalLdapAPI struct {
	InternalFind                 func(*win32.Proc) error
	InternalInit                 func(string, uint32) *ldap.LDAP
	InternalSslInit              func(string, uint32, int32) *ldap.LDAP
	InternalStartTLS             func(*ldap.LDAP, *uint32, **ldap.LDAPMessage, **ldap.LDAPControlW, **ldap.LDAPControlW) uint32
	InternalSetClientCertificate func(*ldap.LDAP, ldap.QUERYCLIENTCERT) uint32
	InternalLastError            func() uint32
	InternalSetOption            func(*ldap.LDAP, int32, unsafe.Pointer) uint32
	InternalGetOption            func(*ldap.LDAP, int32, unsafe.Pointer) uint32
	InternalConnect              func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32
	InternalBind                 func(*ldap.LDAP, *string, foundation.PWSTR, uint32) uint32
	InternalZeroIdentity         func(unsafe.Pointer)
	InternalUnbind               func(*ldap.LDAP) uint32
	InternalSearch               func(*ldap.LDAP, *string, uint32, string, **uint16, uint32, **ldap.LDAPControlW, **ldap.LDAPControlW, uint32, uint32, *uint32) uint32
	InternalResult               func(*ldap.LDAP, uint32, uint32, *ldap.LDAP_TIMEVAL, **ldap.LDAPMessage) uint32
	InternalAbandon              func(*ldap.LDAP, uint32) uint32
	InternalParseResult          func(*ldap.LDAP, *ldap.LDAPMessage, *uint32, *foundation.PWSTR, *foundation.PWSTR, ***uint16, ***ldap.LDAPControlW, foundation.BOOLEAN) uint32
	InternalMessageFree          func(*ldap.LDAPMessage) uint32
	InternalCountEntries         func(*ldap.LDAP, *ldap.LDAPMessage) uint32
	InternalFirstEntry           func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage
	InternalFirstAttribute       func(*ldap.LDAP, *ldap.LDAPMessage, **ldap.BerElement) foundation.PWSTR
	InternalNextAttribute        func(*ldap.LDAP, *ldap.LDAPMessage, *ldap.BerElement) foundation.PWSTR
	InternalValues               func(*ldap.LDAP, *ldap.LDAPMessage, string) **ldap.LDAP_BERVAL
	InternalCountValues          func(**ldap.LDAP_BERVAL) uint32
	InternalValuesFree           func(**ldap.LDAP_BERVAL) uint32
	InternalMemoryFree           func(foundation.PWSTR)
	InternalBerFree              func(*ldap.BerElement, int32)
	InternalCreatePageControl    func(*ldap.LDAP, uint32, *ldap.LDAP_BERVAL, byte, **ldap.LDAPControlW) uint32
	InternalParsePageControl     func(*ldap.LDAP, **ldap.LDAPControlW, *uint32, **ldap.LDAP_BERVAL) uint32
	InternalControlFree          func(*ldap.LDAPControlW) uint32
	InternalControlsFree         func(**ldap.LDAPControlW) uint32
	InternalCookieFree           func(*ldap.LDAP_BERVAL)
	InternalNextEntry            func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage
	InternalGetDN                func(*ldap.LDAP, *ldap.LDAPMessage) foundation.PWSTR
	InternalCountReferences      func(*ldap.LDAP, *ldap.LDAPMessage) uint32
}

func InternalSystemLDAPAPI() InternalLdapAPI {
	return InternalLdapAPI{
		InternalFind:                 func(proc *win32.Proc) error { return proc.Find() },
		InternalInit:                 ldap.Ldap_initW,
		InternalSslInit:              ldap.Ldap_sslinitW,
		InternalStartTLS:             ldap.Ldap_start_tls_s,
		InternalLastError:            ldap.LdapGetLastError,
		InternalSetOption:            ldap.Ldap_set_optionW,
		InternalGetOption:            ldap.Ldap_get_optionW,
		InternalSetClientCertificate: ldap.Ldap_set_client_certificate,
		InternalConnect:              ldap.Ldap_connect,
		InternalBind:                 ldap.Ldap_bind_sW,
		InternalUnbind:               ldap.Ldap_unbind,
		InternalZeroIdentity:         identity.SspiZeroAuthIdentity,
		InternalSearch:               ldap.Ldap_search_extW,
		InternalResult:               ldap.Ldap_result,
		InternalAbandon:              ldap.Ldap_abandon,
		InternalParseResult:          ldap.Ldap_parse_resultW,
		InternalMessageFree:          ldap.Ldap_msgfree,
		InternalCountEntries:         ldap.Ldap_count_entries,
		InternalFirstEntry:           ldap.Ldap_first_entry,
		InternalFirstAttribute:       ldap.Ldap_first_attributeW,
		InternalNextAttribute:        ldap.Ldap_next_attributeW,
		InternalValues:               ldap.Ldap_get_values_lenW,
		InternalCountValues:          ldap.Ldap_count_values_len,
		InternalValuesFree:           ldap.Ldap_value_free_len,
		InternalMemoryFree:           ldap.Ldap_memfreeW,
		InternalBerFree:              ldap.Ber_free,
		InternalCreatePageControl:    ldap.Ldap_create_page_controlW,
		InternalParsePageControl:     ldap.Ldap_parse_page_controlW,
		InternalControlFree:          ldap.Ldap_control_freeW,
		InternalControlsFree:         ldap.Ldap_controls_freeW,
		InternalCookieFree:           ldap.Ber_bvfree,
		InternalNextEntry:            ldap.Ldap_next_entry,
		InternalGetDN:                ldap.Ldap_get_dnW,
		InternalCountReferences:      ldap.Ldap_count_references,
	}
}

func (api InternalLdapAPI) InternalTlsAvailable(transport admodel.Transport) error {
	var proc *win32.Proc
	switch transport {
	case admodel.TransportLDAPS:
		proc = ldap.Procs.Ldap_sslinitW
	case admodel.TransportStartTLS:
		proc = ldap.Procs.Ldap_start_tls_s
	default:
		return nil
	}
	if err := api.InternalFind(proc); err != nil {
		return fmt.Errorf("%w: %w", admodel.ErrUnsupported, err)
	}
	return nil
}

func (api InternalLdapAPI) InternalCredentialAvailable() error {
	if err := api.InternalFind(identity.Procs.SspiZeroAuthIdentity); err != nil {
		return fmt.Errorf("%w: %w", admodel.ErrUnsupported, err)
	}
	return nil
}

func (api InternalLdapAPI) InternalAvailable() error {
	for _, proc := range []*win32.Proc{
		ldap.Procs.Ldap_initW, ldap.Procs.LdapGetLastError, ldap.Procs.Ldap_set_optionW, ldap.Procs.Ldap_get_optionW,
		ldap.Procs.Ldap_connect, ldap.Procs.Ldap_bind_sW, ldap.Procs.Ldap_unbind,
		ldap.Procs.Ldap_search_extW, ldap.Procs.Ldap_result, ldap.Procs.Ldap_abandon,
		ldap.Procs.Ldap_parse_resultW, ldap.Procs.Ldap_msgfree, ldap.Procs.Ldap_count_entries, ldap.Procs.Ldap_first_entry,
		ldap.Procs.Ldap_first_attributeW, ldap.Procs.Ldap_next_attributeW, ldap.Procs.Ldap_get_values_lenW,
		ldap.Procs.Ldap_count_values_len, ldap.Procs.Ldap_value_free_len, ldap.Procs.Ldap_memfreeW, ldap.Procs.Ber_free,
	} {
		if err := api.InternalFind(proc); err != nil {
			return fmt.Errorf("%w: %w", admodel.ErrUnsupported, err)
		}
	}
	return nil
}
