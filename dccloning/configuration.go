package dccloning

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const ConfigFileName = "DCCloneConfig.xml"

var (
	ErrInvalidConfiguration = errors.New("invalid DC clone configuration")
	ErrClonePrerequisite    = errors.New("DC cloning prerequisite was not satisfied")
)

// CloneConfiguration describes the clone, not the source computer. Empty names
// leave name/site selection to the cloning service. IPv6 settings contain DNS
// resolvers only; the Microsoft schema has no IPv6 address or gateway fields.
// Static selects StaticSettings for every configured family.
type CloneConfiguration struct {
	ComputerName       string   `json:"computer_name,omitempty"`
	SiteName           string   `json:"site_name,omitempty"`
	Static             bool     `json:"static"`
	IPv4Address        string   `json:"ipv4_address,omitempty"`
	IPv4SubnetMask     string   `json:"ipv4_subnet_mask,omitempty"`
	IPv4DefaultGateway string   `json:"ipv4_default_gateway,omitempty"`
	IPv4DNSResolvers   []string `json:"ipv4_dns_resolvers,omitempty"`
	IPv6DNSResolvers   []string `json:"ipv6_dns_resolvers,omitempty"`
}

// ConfigOptions selects online preparation by default. Offline explicitly skips
// all host/directory/application checks and replaces an existing ConfigFileName,
// matching the documented offline behavior. Offline requires Directory. Online
// defaults to the local DSA Working Directory and never replaces an existing
// configuration. Neither mode starts, stops, exports, or clones a machine.
type ConfigOptions struct {
	Configuration CloneConfiguration
	Directory     string
	Offline       bool
	// Timeout bounds the whole operation, including directory reads and waiting
	// between host calls. Zero uses 30 seconds; a caller context may be shorter.
	Timeout time.Duration
}

// ConfigPrerequisites records completed observations, including partial results
// on failure. Complete means these preparation checks passed; it does not prove
// that an eventual clone will succeed or assess application-vendor support.
// CloneableGroupMember checks the documented group prerequisite, not arbitrary
// changes to the domain's clone-control-access-right ACL.
type ConfigPrerequisites struct {
	Role                  Role    `json:"role"`
	SourceHost            string  `json:"source_host,omitempty"`
	SourceComputerDN      string  `json:"source_computer_dn,omitempty"`
	GenerationIDAvailable bool    `json:"generation_id_available"`
	PrimaryController     string  `json:"primary_controller,omitempty"`
	PrimaryFunctionality  *uint32 `json:"primary_functionality,omitempty"`
	CloneableGroupMember  bool    `json:"cloneable_group_member"`
	Applications          Result  `json:"applications"`
	Complete              bool    `json:"complete"`
}

// Configured preserves publication uncertainty independently of prerequisite
// results. Offline results always have ChecksSkipped true and Complete false.
type Configured struct {
	Path          string              `json:"path"`
	Outcome       WriteOutcome        `json:"outcome"`
	ChecksSkipped bool                `json:"checks_skipped"`
	Prerequisites ConfigPrerequisites `json:"prerequisites"`
}

// GenerateConfig validates and writes one clone configuration. Native execution
// requires Windows amd64/arm64. EncodeCloneConfiguration is portable. Online
// directory reads have a whole-operation deadline; synchronous host/locator
// APIs can delay cancellation. Publication is never retried or called rollback.
func GenerateConfig(ctx context.Context, options ConfigOptions) (Configured, error) {
	if options.Timeout < 0 {
		return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, ErrInvalidConfiguration
	}
	configuration, err := options.Configuration.normalized()
	if err != nil {
		return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, err
	}
	options.Configuration = configuration
	if strings.ContainsRune(options.Directory, 0) || !utf8.ValidString(options.Directory) || (options.Offline && strings.TrimSpace(options.Directory) == "") {
		return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, ErrInvalidPath
	}
	if !options.Offline && configuration.hasIPv4() && len(configuration.IPv6DNSResolvers) != 0 {
		return Configured{Outcome: NotWritten}, fmt.Errorf("%w: online preparation accepts one IP family; use explicit offline mode for dual stack", ErrInvalidConfiguration)
	}
	if err := context.Cause(ctx); err != nil {
		return Configured{Outcome: NotWritten, ChecksSkipped: options.Offline}, err
	}
	if options.Timeout == 0 {
		options.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	return generateConfigNative(ctx, options)
}

// Validate checks configuration syntax without contacting a directory or
// loading Windows APIs. It does not check site/name uniqueness or reachability.
func (c CloneConfiguration) Validate() error { _, err := c.normalized(); return err }

func (c CloneConfiguration) hasIPv4() bool {
	return c.IPv4Address != "" || c.IPv4SubnetMask != "" || c.IPv4DefaultGateway != "" || len(c.IPv4DNSResolvers) != 0
}

func (c CloneConfiguration) normalized() (CloneConfiguration, error) {
	c.ComputerName = strings.TrimSpace(c.ComputerName)
	c.SiteName = strings.TrimSpace(c.SiteName)
	if c.ComputerName != "" && !validCloneComputerName(c.ComputerName) {
		return c, fmt.Errorf("%w: computer name must be a nonnumeric DNS label of at most 15 ASCII characters", ErrInvalidConfiguration)
	}
	if !validXMLText(c.SiteName) || len(utf16.Encode([]rune(c.SiteName))) > 255 || strings.IndexFunc(c.SiteName, unicode.IsControl) >= 0 {
		return c, fmt.Errorf("%w: invalid site name", ErrInvalidConfiguration)
	}
	var err error
	if c.IPv4DNSResolvers, err = normalizeResolvers(c.IPv4DNSResolvers, true); err != nil {
		return c, err
	}
	if c.IPv6DNSResolvers, err = normalizeResolvers(c.IPv6DNSResolvers, false); err != nil {
		return c, err
	}
	c.IPv4Address = strings.TrimSpace(c.IPv4Address)
	c.IPv4SubnetMask = strings.TrimSpace(c.IPv4SubnetMask)
	c.IPv4DefaultGateway = strings.TrimSpace(c.IPv4DefaultGateway)
	if !c.Static && (c.IPv4Address != "" || c.IPv4SubnetMask != "" || c.IPv4DefaultGateway != "") {
		return c, fmt.Errorf("%w: IPv4 address/mask/gateway require static settings", ErrInvalidConfiguration)
	}
	if c.Static && !c.hasIPv4() && len(c.IPv6DNSResolvers) == 0 {
		return c, fmt.Errorf("%w: static settings require IPv4 configuration or IPv6 DNS resolvers", ErrInvalidConfiguration)
	}
	if c.Static && c.hasIPv4() {
		if !validConfigAddress(c.IPv4Address, true) || len(c.IPv4DNSResolvers) == 0 || !validSubnetMask(c.IPv4SubnetMask) {
			return c, fmt.Errorf("%w: static IPv4 requires an address, contiguous subnet mask and DNS resolver", ErrInvalidConfiguration)
		}
		if c.IPv4DefaultGateway != "" && !validConfigAddress(c.IPv4DefaultGateway, true) {
			return c, fmt.Errorf("%w: invalid IPv4 gateway", ErrInvalidConfiguration)
		}
	}
	return c, nil
}

func validCloneComputerName(name string) bool {
	if len(name) == 0 || len(name) > 15 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	onlyDigits := true
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' {
			onlyDigits = false
		} else if r < '0' || r > '9' {
			return false
		}
	}
	return !onlyDigits
}

func normalizeResolvers(values []string, ipv4 bool) ([]string, error) {
	if len(values) > 4 {
		return nil, fmt.Errorf("%w: at most four DNS resolvers per family", ErrInvalidConfiguration)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validConfigAddress(value, ipv4) {
			return nil, fmt.Errorf("%w: invalid DNS resolver address/family", ErrInvalidConfiguration)
		}
		result = append(result, value)
	}
	return result, nil
}

func validConfigAddress(value string, ipv4 bool) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() == ipv4 && !address.Is4In6() && address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
}

func validSubnetMask(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() {
		return false
	}
	bytes := address.As4()
	mask := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
	inverse := ^mask
	return mask != 0 && inverse&(inverse+1) == 0
}
