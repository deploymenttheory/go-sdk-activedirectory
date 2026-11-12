package dccloning

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

type configConnection interface {
	RootDSE(context.Context, ad.RootDSEOptions) (ad.RootDSE, error)
	Search(context.Context, ad.SearchOptions) (ad.SearchResult, error)
	Close() error
}

type configDirectoryAPI struct {
	dial     func(context.Context, ad.Config) (configConnection, error)
	discover func(context.Context, ad.DiscoveryOptions) (ad.DiscoveredController, error)
}

func checkCloneDirectory(ctx context.Context, sourceHost string, api configDirectoryAPI, evidence *ConfigPrerequisites) (resultErr error) {
	source, err := api.dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: sourceHost}, Timeout: 10 * time.Second})
	if err != nil {
		return fmt.Errorf("bind local clone source: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	root, err := source.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return fmt.Errorf("read source RootDSE: %w", err)
	}
	if err := validateCloneRoot(root, sourceHost); err != nil {
		return err
	}
	if root.ServerName == nil || *root.ServerName == "" {
		return fmt.Errorf("%w: source serverName is absent", ErrIncomplete)
	}
	server, err := cloneObject(ctx, source, *root.ServerName, []string{"serverReference"})
	if err != nil {
		return err
	}
	computerDN, err := cloneText(server, "serverReference")
	if err != nil {
		return err
	}
	evidence.SourceComputerDN = computerDN
	computer, err := cloneObject(ctx, source, computerDN, []string{"objectGUID", "objectSid"})
	if err != nil {
		return err
	}
	guid, err := cloneScalar(computer, "objectGUID")
	if err != nil || len(guid) != 16 {
		return errors.Join(err, fmt.Errorf("%w: source computer GUID", ErrIncomplete))
	}
	sid, err := cloneScalar(computer, "objectSid")
	if err != nil || !validCloneSID(sid) {
		return errors.Join(err, fmt.Errorf("%w: source computer SID", ErrIncomplete))
	}
	// A locator advertisement is not proof of current PDC ownership or bind
	// availability. Re-read both after establishing the integrated connection.
	pdc, err := api.discover(ctx, ad.DiscoveryOptions{Services: ad.ServicePrimaryDC, MinimumVersion: ad.DirectoryServiceWindows2012, ForceDiscover: true})
	if err != nil {
		return fmt.Errorf("locate cloning PDC: %w", err)
	}
	endpoint, err := pdc.Endpoint()
	if err != nil {
		return fmt.Errorf("cloning PDC endpoint: %w", err)
	}
	evidence.PrimaryController = endpoint.Host
	primary, err := api.dial(ctx, ad.Config{Endpoint: endpoint, Timeout: 10 * time.Second})
	if err != nil {
		return fmt.Errorf("bind cloning PDC: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, primary.Close()) }()
	primaryRoot, err := primary.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return fmt.Errorf("read cloning PDC RootDSE: %w", err)
	}
	evidence.PrimaryFunctionality = primaryRoot.DomainControllerFunctionality
	if err := validateCloneRoot(primaryRoot, endpoint.Host); err != nil {
		return err
	}
	if !strings.EqualFold(*root.DefaultNamingContext, *primaryRoot.DefaultNamingContext) || primaryRoot.DSServiceName == nil || *primaryRoot.DSServiceName == "" {
		return fmt.Errorf("%w: PDC naming context/DSA identity differs", ErrClonePrerequisite)
	}
	domain, err := cloneObject(ctx, primary, *root.DefaultNamingContext, []string{"objectSid", "fSMORoleOwner"})
	if err != nil {
		return err
	}
	owner, err := cloneText(domain, "fSMORoleOwner")
	if err != nil {
		return err
	}
	if !strings.EqualFold(owner, *primaryRoot.DSServiceName) {
		return fmt.Errorf("%w: discovered server does not own the PDC role", ErrClonePrerequisite)
	}
	domainSID, err := cloneScalar(domain, "objectSid")
	if err != nil {
		return err
	}
	groupSID, err := cloneGroupSID(domainSID)
	if err != nil {
		return err
	}
	membership, err := cloneObject(ctx, primary, computerDN, []string{"objectGUID", "objectSid", "tokenGroups"})
	if err != nil {
		return err
	}
	primaryGUID, guidErr := cloneScalar(membership, "objectGUID")
	primarySID, sidErr := cloneScalar(membership, "objectSid")
	if guidErr != nil || sidErr != nil || !bytes.Equal(guid, primaryGUID) || !bytes.Equal(sid, primarySID) {
		return errors.Join(guidErr, sidErr, fmt.Errorf("%w: source computer identity differs on PDC", ErrClonePrerequisite))
	}
	groups, state := membership.Attribute("tokenGroups")
	if state != ad.AttributePresent || len(groups) == 0 {
		return fmt.Errorf("%w: tokenGroups is unavailable; authorization is unknown", ErrIncomplete)
	}
	for _, group := range groups {
		if !validCloneSID(group) {
			return fmt.Errorf("%w: malformed tokenGroups SID", ErrIncomplete)
		}
		evidence.CloneableGroupMember = evidence.CloneableGroupMember || bytes.Equal(group, groupSID)
	}
	if !evidence.CloneableGroupMember {
		return fmt.Errorf("%w: source is not a member of Cloneable Domain Controllers", ErrClonePrerequisite)
	}
	return context.Cause(ctx)
}

func validateCloneRoot(root ad.RootDSE, host string) error {
	if err := root.Capabilities().RequireADDS("DC clone configuration"); err != nil {
		return fmt.Errorf("clone directory capability: %w", err)
	}
	if root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, host) || root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" || root.DomainControllerFunctionality == nil {
		return fmt.Errorf("%w: clone RootDSE host/domain/functionality is incomplete", ErrIncomplete)
	}
	if *root.DomainControllerFunctionality < 5 {
		return fmt.Errorf("%w: DC must support Windows Server 2012 functionality", ErrClonePrerequisite)
	}
	return nil
}

func cloneObject(ctx context.Context, connection configConnection, dn string, properties []string) (ad.Object, error) {
	result, err := connection.Search(ctx, ad.SearchOptions{Base: dn, Scope: ad.ScopeBase, Properties: properties})
	if err != nil {
		return ad.Object{}, fmt.Errorf("read clone prerequisite object: %w", err)
	}
	if !result.Complete || len(result.Objects) != 1 || !strings.EqualFold(result.Objects[0].DistinguishedName, dn) {
		return ad.Object{}, fmt.Errorf("%w: clone prerequisite object identity/count", ErrIncomplete)
	}
	return result.Objects[0], nil
}

func cloneScalar(object ad.Object, name string) ([]byte, error) {
	values, state := object.Attribute(name)
	if state != ad.AttributePresent || len(values) != 1 || len(values[0]) == 0 {
		return nil, fmt.Errorf("%w: clone prerequisite %s is missing or multivalued", ErrIncomplete, name)
	}
	return values[0], nil
}

func cloneText(object ad.Object, name string) (string, error) {
	value, err := cloneScalar(object, name)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) || bytes.ContainsRune(value, 0) {
		return "", fmt.Errorf("%w: clone prerequisite %s is malformed", ErrIncomplete, name)
	}
	return string(value), nil
}

func validCloneSID(value []byte) bool {
	return len(value) >= 8 && value[0] == 1 && value[1] <= 15 && len(value) == 8+4*int(value[1])
}

func cloneGroupSID(domain []byte) ([]byte, error) {
	if !validCloneSID(domain) || domain[1] != 4 || !bytes.Equal(domain[2:8], []byte{0, 0, 0, 0, 0, 5}) || binary.LittleEndian.Uint32(domain[8:12]) != 21 {
		return nil, fmt.Errorf("%w: malformed AD DS domain SID", ErrIncomplete)
	}
	group := make([]byte, len(domain)+4)
	copy(group, domain)
	group[1]++
	binary.LittleEndian.PutUint32(group[len(domain):], 522)
	return group, nil
}
