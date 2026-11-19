package engine

import (
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalValidateDiscoveryIdentity(read *InternalDirectoryRead, selection admodel.DomainControllerSelection, result *admodel.AuthenticatedController) {
	root := read.InternalObservation.RootDSE
	domain := read.InternalRequire(root.DefaultNamingContext, "defaultNamingContext")
	host := read.InternalRequire(root.DNSHostName, "dnsHostName")
	configuration := read.InternalRequire(root.ConfigurationNamingContext, "configurationNamingContext")
	server := read.InternalRequire(root.ServerName, "serverName")
	dsa := read.InternalRequire(root.DSServiceName, "dsServiceName")
	if read.InternalErr != nil {
		return
	}
	result.DomainDN = &domain
	result.HostName = &host
	result.ServerDN = &server
	result.DSADN = &dsa
	if !admodel.InternalTopologySameDN(domain, internalDiscoveryDomainDN(selection.DomainDNS)) || !internalDiscoverySameHost(host, read.InternalClient.config.Endpoint.Host) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	parent, err := admodel.InternalParentDirectoryDN(dsa)
	if err != nil || !admodel.InternalTopologySameDN(parent, server) || !internalDiscoveryWithin(server, configuration) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	internalDiscoveryDomainIdentity(read, selection, result, domain, configuration)
	if read.InternalErr != nil {
		return
	}
	serverObject := internalDiscoveryOne(read, server, "server", []string{"objectGUID", "objectClass", "dnsHostName", "serverReference"})
	result.ServerGUID = internalDiscoveryGUID(read, serverObject)
	serverHost := internalDiscoveryText(read, serverObject, "dnshostname")
	computer := internalDiscoveryText(read, serverObject, "serverreference")
	if read.InternalErr != nil {
		return
	}
	result.ComputerDN = &computer
	if !internalDiscoverySameHost(serverHost, host) || !internalDiscoveryWithin(computer, domain) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	dsaObject := internalDiscoveryOne(read, dsa, "nTDSDSA", []string{"objectGUID", "objectClass", "msDS-HasDomainNCs"})
	result.DSAGUID = internalDiscoveryGUID(read, dsaObject)
	if result.DSAGUID != nil && !internalDiscoveryGUIDMatches(selection.ExpectedDSAGUID, result.DSAGUID) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
	values, state := dsaObject.Attribute("msds-hasdomainncs")
	if state != admodel.AttributePresent {
		read.InternalAdd(admodel.ErrIncompleteResult)
	} else {
		found := false
		for _, value := range values {
			if admodel.InternalTopologySameDN(string(value), domain) {
				found = true
			}
		}
		if !found {
			read.InternalAdd(admodel.ErrDiscoveryIdentity)
		}
	}
	if read.InternalErr != nil {
		return
	}
	computerObject := internalDiscoveryOne(read, computer, "computer", []string{"objectGUID", "objectClass", "dnsHostName", "objectSid"})
	result.ComputerGUID = internalDiscoveryGUID(read, computerObject)
	computerHost := internalDiscoveryText(read, computerObject, "dnshostname")
	if computerHost != "" && !internalDiscoverySameHost(computerHost, host) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
	internalDiscoveryComputerSID(read, computerObject, result.DomainSID)
	if read.InternalErr == nil && selection.SiteName != "" {
		internalDiscoverySite(read, server, configuration, selection.SiteName, result)
	}
}

func internalDiscoveryDomainIdentity(
	read *InternalDirectoryRead,
	selection admodel.DomainControllerSelection,
	result *admodel.AuthenticatedController,
	domain, configuration string,
) {
	object := internalDiscoveryOne(read, domain, "domainDNS", []string{"objectGUID", "objectClass", "objectSid"})
	result.DomainGUID = internalDiscoveryGUID(read, object)
	sid := internalDiscoveryBytes(read, object, "objectsid")
	if len(sid) > 0 && admodel.InternalValidDomainSID(sid) {
		parsed, _ := admodel.SIDFromBytes(sid)
		text := parsed.String()
		result.DomainSID = &text
	} else if len(sid) > 0 {
		read.InternalAdd(admodel.ErrInvalidResult)
	}
	if result.DomainGUID != nil && !internalDiscoveryGUIDMatches(selection.ExpectedDomainGUID, result.DomainGUID) ||
		selection.ExpectedDomainSID != "" && result.DomainSID != nil && !internalDiscoverySIDMatches(selection.ExpectedDomainSID, result.DomainSID) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
	if read.InternalErr != nil {
		return
	}
	base := "CN=Partitions," + configuration
	search := read.InternalSearch(
		admodel.SearchOptions{
			Base:       base,
			Scope:      admodel.ScopeOneLevel,
			Filter:     "(&(objectClass=crossRef)(nCName=" + admodel.InternalLdapLiteral(domain) + "))",
			Properties: append(admodel.InternalCrossReferenceAttributes(), "objectClass"),
		},
	)
	if len(search.Objects) != 1 {
		if len(search.Objects) > 1 {
			read.InternalAdd(admodel.ErrDiscoveryAmbiguous)
		} else {
			read.InternalAdd(admodel.ErrIncompleteResult)
		}
		return
	}
	raw := search.Objects[0]
	classes, classState := raw.Attribute("objectclass")
	if classState != admodel.AttributePresent {
		read.InternalAdd(admodel.ErrIncompleteResult)
		return
	}
	isCrossRef := false
	for _, class := range classes {
		if strings.EqualFold(string(class), "crossRef") {
			isCrossRef = true
		}
	}
	if !isCrossRef {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	parent, err := admodel.InternalParentDirectoryDN(raw.DistinguishedName)
	if err != nil || !admodel.InternalTopologySameDN(parent, base) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
	ref := admodel.CrossReference{
		Raw:           raw,
		NamingContext: decoder.InternalText("nCName"),
		DNSRoot:       decoder.InternalText("dnsRoot"),
		NetBIOSName:   decoder.InternalText("nETBIOSName"),
		Enabled:       admodel.InternalDecodeScalar(&decoder, "enabled", admodel.InternalParseLDAPBool),
		SystemFlags:   admodel.InternalDecodeScalar(&decoder, "systemFlags", admodel.InternalParseDirectoryMask),
	}
	result.CrossReference = &ref
	result.DomainDNS = ref.DNSRoot
	for _, decodeErr := range decoder.InternalErrors {
		read.InternalAdd(decodeErr)
	}
	if ref.NamingContext == nil || ref.DNSRoot == nil || ref.SystemFlags == nil {
		read.InternalAdd(admodel.ErrIncompleteResult)
		return
	}
	if !admodel.InternalTopologySameDN(*ref.NamingContext, domain) || !strings.EqualFold(strings.TrimSuffix(*ref.DNSRoot, "."), selection.DomainDNS) || *ref.SystemFlags&3 != 3 ||
		ref.Enabled != nil && !*ref.Enabled {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
}

func internalDiscoverySameHost(first, second string) bool {
	return admodel.InternalValidDiscoveryHost(first) && admodel.InternalValidDiscoveryHost(second) &&
		strings.EqualFold(strings.TrimSuffix(first, "."), strings.TrimSuffix(second, "."))
}

func internalDiscoveryWithin(dn, base string) bool {
	parsed, err := admodel.InternalParseIdentityDN(dn)
	ancestor, e := admodel.InternalParseIdentityDN(base)
	return err == nil && e == nil && len(parsed) > len(ancestor) && admodel.InternalIdentityWithin(parsed, ancestor)
}
