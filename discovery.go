package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	ErrInvalidDiscovery    = errors.New("invalid directory discovery options")
	ErrInvalidNativeResult = errors.New("invalid Windows directory result")
	ErrNoCurrentDomain     = errors.New("the selected Windows domain context is unavailable")
)

// NativeStatusError preserves a Windows status independently of LDAP status.
// Operation identifies the native API; Code is its returned Win32 status.
type NativeStatusError struct {
	Operation string
	Code      uint32
}

func (e *NativeStatusError) Error() string {
	return fmt.Sprintf("%s: Windows status %d", e.Operation, e.Code)
}

// DomainNameFormat distinguishes DNS names from NetBIOS domain names. A short
// DNS name and a NetBIOS name are not interchangeable on all Windows policies.
type DomainNameFormat uint8

const (
	DomainNameDNS DomainNameFormat = iota
	DomainNameNetBIOS
)

// DomainName is a name used for domain selection, not an authenticated identity.
type DomainName struct {
	Name   string
	Format DomainNameFormat
}

func (d DomainName) validate() error {
	if d.Format > DomainNameNetBIOS || !validDiscoveryText(d.Name) ||
		strings.ContainsAny(d.Name, `/\:*?"<>|@[]`) || strings.IndexFunc(d.Name, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: invalid domain name or format", ErrInvalidDiscovery)
	}
	if d.Format == DomainNameNetBIOS {
		if len(utf16.Encode([]rune(d.Name))) > 15 || strings.HasPrefix(d.Name, ".") {
			return fmt.Errorf("%w: invalid NetBIOS domain name", ErrInvalidDiscovery)
		}
	} else {
		name := strings.TrimSuffix(d.Name, ".")
		if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
			return fmt.Errorf("%w: invalid DNS domain name", ErrInvalidDiscovery)
		}
	}
	return nil
}

// DCServices is a set of required or advertised domain-controller services.
type DCServices uint8

const (
	ServicePrimaryDC DCServices = 1 << iota
	ServiceGlobalCatalog
	ServiceKDC
	ServiceTime
	ServiceADWS
)

// DirectoryServiceVersion selects a minimum DC service generation. It is not
// a domain/forest functional level or a schema version.
type DirectoryServiceVersion uint8

const (
	DirectoryServiceWindows2000 DirectoryServiceVersion = iota
	DirectoryServiceWindows2008
	DirectoryServiceWindows2012
	DirectoryServiceWindows2012R2
	DirectoryServiceWindows2016
)

// DiscoveryOptions selects one candidate using the local Windows DC Locator.
// Nil Domain uses the local computer's domain (its forest for GC discovery).
// For ServiceGlobalCatalog, an explicit Domain must identify the forest root.
// Discovery does not authenticate or bind, and has no explicit credentials.
type DiscoveryOptions struct {
	Domain         *DomainName
	SiteName       string
	Services       DCServices
	MinimumVersion DirectoryServiceVersion
	Writable       bool
	// AvoidSelf excludes the local host when the local host is a DC. Windows
	// ignores this criterion on a member or an unjoined computer.
	AvoidSelf     bool
	ForceDiscover bool
	// PreferReliableTimeService permits fallback to an ordinary time server.
	PreferReliableTimeService bool
	// NextClosestSite tries another nearby site, then any suitable site. It
	// cannot accompany SiteName or ServicePrimaryDC.
	NextClosestSite bool
}

func validDiscoveryText(s string) bool {
	return s != "" && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0 &&
		len(utf16.Encode([]rune(s))) <= 255
}

func (o DiscoveryOptions) normalized() (DiscoveryOptions, error) {
	if o.Domain != nil {
		if err := o.Domain.validate(); err != nil {
			return DiscoveryOptions{}, err
		}
		domain := *o.Domain
		o.Domain = &domain
	}
	const known = ServicePrimaryDC | ServiceGlobalCatalog | ServiceKDC | ServiceTime | ServiceADWS
	if o.Services & ^known != 0 || o.MinimumVersion > DirectoryServiceWindows2016 {
		return DiscoveryOptions{}, fmt.Errorf("%w: unknown service or minimum version", ErrInvalidDiscovery)
	}
	exclusive := o.Services & (ServicePrimaryDC | ServiceGlobalCatalog | ServiceKDC)
	if exclusive != 0 && exclusive&(exclusive-1) != 0 {
		return DiscoveryOptions{}, fmt.Errorf("%w: primary DC, global catalog and KDC criteria are mutually exclusive", ErrInvalidDiscovery)
	}
	if o.SiteName != "" && !validDiscoveryText(o.SiteName) {
		return DiscoveryOptions{}, fmt.Errorf("%w: invalid site name", ErrInvalidDiscovery)
	}
	if o.NextClosestSite && (o.SiteName != "" || o.Services&ServicePrimaryDC != 0) {
		return DiscoveryOptions{}, fmt.Errorf("%w: next-closest-site conflicts with an explicit site or primary DC", ErrInvalidDiscovery)
	}
	return o, nil
}

// Validate checks portable input constraints without loading Windows APIs.
// Windows validates domain/site existence and host-dependent locator policy.
func (o DiscoveryOptions) Validate() error { _, err := o.normalized(); return err }

// ControllerAddressType identifies the native address representation. Unknown
// values are preserved. The IP form still carries the native leading slashes.
type ControllerAddressType uint32

const (
	ControllerAddressIP      ControllerAddressType = 1
	ControllerAddressNetBIOS ControllerAddressType = 2
)

// DiscoveredController owns copied locator data. It is an advertised candidate,
// not an authenticated LDAP result or a complete DomainController projection.
// Native names/addresses retain their leading backslashes. Optional strings
// distinguish native NULL from an empty string; unknown native flags survive.
type DiscoveredController struct {
	Requested           DiscoveryOptions
	ControllerName      string
	ControllerAddress   string
	AddressType         ControllerAddressType
	DomainGUID          string
	DomainName          string
	ForestName          *string
	DCSiteName          *string
	ClientSiteName      *string
	NativeFlags         uint32
	Services            DCServices
	Writable            bool
	ReadOnly            bool
	ReliableTimeService bool
}

// Endpoint derives a DNS LDAP endpoint from the copied native controller name.
// The caller selects authentication, transport and port when constructing Config.
// Successful conversion does not prove the endpoint is reachable or authentic.
// A name outside the connection API's accepted host syntax remains available in
// ControllerName even when Endpoint cannot convert it.
func (d DiscoveredController) Endpoint() (Endpoint, error) {
	host := strings.TrimPrefix(d.ControllerName, `\\`)
	if !validServerHost(host) {
		return Endpoint{}, fmt.Errorf("%w: locator did not return a usable DNS host", ErrInvalidNativeResult)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return Endpoint{}, fmt.Errorf("%w: locator returned an IP address instead of a DNS host", ErrInvalidNativeResult)
	}
	return Endpoint{Host: host}, nil
}

// DiscoverDomainController invokes the local DC Locator. Cached results are
// allowed unless ForceDiscover is set. A returned candidate must be explicitly
// authenticated before use. Cancellation is checked between native calls: the
// synchronous locator itself has no interrupt or timeout parameter and may
// delay return. Data may be returned with a cleanup/cancellation error.
func DiscoverDomainController(ctx context.Context, options DiscoveryOptions) (DiscoveredController, error) {
	options, err := options.normalized()
	if err != nil {
		return DiscoveredController{}, err
	}
	if err := context.Cause(ctx); err != nil {
		return DiscoveredController{}, err
	}
	return discoverDomainControllerNative(ctx, options)
}

// CurrentMode explicitly selects the source of the current domain name.
type CurrentMode uint8

const (
	CurrentLocalComputer CurrentMode = iota + 1
	CurrentLoggedOnUser
)

// CurrentDomain returns a name from local-computer join status or the calling
// thread's security identity. It does not authenticate or return domain metadata.
// A caller using thread impersonation must keep its goroutine on that OS thread.
// Explicit LDAP credentials do not affect this operation. Native calls are
// synchronous; cancellation is observed between calls, not by interrupting them.
func CurrentDomain(ctx context.Context, mode CurrentMode) (DomainName, error) {
	if mode != CurrentLocalComputer && mode != CurrentLoggedOnUser {
		return DomainName{}, fmt.Errorf("%w: select local computer or logged-on user", ErrInvalidDiscovery)
	}
	if err := context.Cause(ctx); err != nil {
		return DomainName{}, err
	}
	return currentDomainNative(ctx, mode)
}
