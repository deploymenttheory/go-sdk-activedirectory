//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"fmt"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
)

// Each session owns its boundary, so failure/lifetime tests never replace
// process-wide callbacks. Types and dispatch come from the pinned bindings.
type ldapAPI struct {
	find              func(*win32.Proc) error
	init              func(string, uint32) *ldap.LDAP
	lastError         func() uint32
	setOption         func(*ldap.LDAP, int32, unsafe.Pointer) uint32
	getOption         func(*ldap.LDAP, int32, unsafe.Pointer) uint32
	connect           func(*ldap.LDAP, *ldap.LDAP_TIMEVAL) uint32
	bind              func(*ldap.LDAP, *string, foundation.PWSTR, uint32) uint32
	zeroIdentity      func(unsafe.Pointer)
	unbind            func(*ldap.LDAP) uint32
	search            func(*ldap.LDAP, *string, uint32, string, **uint16, uint32, **ldap.LDAPControlW, **ldap.LDAPControlW, uint32, uint32, *uint32) uint32
	result            func(*ldap.LDAP, uint32, uint32, *ldap.LDAP_TIMEVAL, **ldap.LDAPMessage) uint32
	abandon           func(*ldap.LDAP, uint32) uint32
	parseResult       func(*ldap.LDAP, *ldap.LDAPMessage, *uint32, *foundation.PWSTR, *foundation.PWSTR, ***uint16, ***ldap.LDAPControlW, foundation.BOOLEAN) uint32
	messageFree       func(*ldap.LDAPMessage) uint32
	countEntries      func(*ldap.LDAP, *ldap.LDAPMessage) uint32
	firstEntry        func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage
	firstAttribute    func(*ldap.LDAP, *ldap.LDAPMessage, **ldap.BerElement) foundation.PWSTR
	nextAttribute     func(*ldap.LDAP, *ldap.LDAPMessage, *ldap.BerElement) foundation.PWSTR
	values            func(*ldap.LDAP, *ldap.LDAPMessage, string) **ldap.LDAP_BERVAL
	countValues       func(**ldap.LDAP_BERVAL) uint32
	valuesFree        func(**ldap.LDAP_BERVAL) uint32
	memoryFree        func(foundation.PWSTR)
	berFree           func(*ldap.BerElement, int32)
	createPageControl func(*ldap.LDAP, uint32, *ldap.LDAP_BERVAL, byte, **ldap.LDAPControlW) uint32
	parsePageControl  func(*ldap.LDAP, **ldap.LDAPControlW, *uint32, **ldap.LDAP_BERVAL) uint32
	controlFree       func(*ldap.LDAPControlW) uint32
	controlsFree      func(**ldap.LDAPControlW) uint32
	cookieFree        func(*ldap.LDAP_BERVAL)
	nextEntry         func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage
	getDN             func(*ldap.LDAP, *ldap.LDAPMessage) foundation.PWSTR
	countReferences   func(*ldap.LDAP, *ldap.LDAPMessage) uint32
}

func systemLDAPAPI() ldapAPI {
	return ldapAPI{
		find: func(proc *win32.Proc) error { return proc.Find() },
		init: ldap.Ldap_initW, lastError: ldap.LdapGetLastError,
		setOption: ldap.Ldap_set_optionW, getOption: ldap.Ldap_get_optionW,
		connect: ldap.Ldap_connect, bind: ldap.Ldap_bind_sW, unbind: ldap.Ldap_unbind,
		zeroIdentity: identity.SspiZeroAuthIdentity,
		search:       ldap.Ldap_search_extW, result: ldap.Ldap_result, abandon: ldap.Ldap_abandon,
		parseResult: ldap.Ldap_parse_resultW, messageFree: ldap.Ldap_msgfree,
		countEntries: ldap.Ldap_count_entries, firstEntry: ldap.Ldap_first_entry,
		firstAttribute: ldap.Ldap_first_attributeW, nextAttribute: ldap.Ldap_next_attributeW,
		values: ldap.Ldap_get_values_lenW, countValues: ldap.Ldap_count_values_len,
		valuesFree: ldap.Ldap_value_free_len, memoryFree: ldap.Ldap_memfreeW, berFree: ldap.Ber_free,
		createPageControl: ldap.Ldap_create_page_controlW, parsePageControl: ldap.Ldap_parse_page_controlW,
		controlFree: ldap.Ldap_control_freeW, controlsFree: ldap.Ldap_controls_freeW, cookieFree: ldap.Ber_bvfree,
		nextEntry: ldap.Ldap_next_entry, getDN: ldap.Ldap_get_dnW, countReferences: ldap.Ldap_count_references,
	}
}

func (api ldapAPI) credentialAvailable() error {
	if err := api.find(identity.Procs.SspiZeroAuthIdentity); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupported, err)
	}
	return nil
}

func (api ldapAPI) available() error {
	for _, proc := range []*win32.Proc{
		ldap.Procs.Ldap_initW, ldap.Procs.LdapGetLastError, ldap.Procs.Ldap_set_optionW, ldap.Procs.Ldap_get_optionW,
		ldap.Procs.Ldap_connect, ldap.Procs.Ldap_bind_sW, ldap.Procs.Ldap_unbind,
		ldap.Procs.Ldap_search_extW, ldap.Procs.Ldap_result, ldap.Procs.Ldap_abandon,
		ldap.Procs.Ldap_parse_resultW, ldap.Procs.Ldap_msgfree, ldap.Procs.Ldap_count_entries, ldap.Procs.Ldap_first_entry,
		ldap.Procs.Ldap_first_attributeW, ldap.Procs.Ldap_next_attributeW, ldap.Procs.Ldap_get_values_lenW,
		ldap.Procs.Ldap_count_values_len, ldap.Procs.Ldap_value_free_len, ldap.Procs.Ldap_memfreeW, ldap.Procs.Ber_free,
	} {
		if err := api.find(proc); err != nil {
			return fmt.Errorf("%w: %w", ErrUnsupported, err)
		}
	}
	return nil
}
