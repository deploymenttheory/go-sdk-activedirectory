package engine

import (
	"bytes"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalDiscoveryOne(read *InternalDirectoryRead, dn, class string, properties []string) admodel.Object {
	object := read.InternalOne(dn, "(objectClass="+class+")", properties)
	if object.DistinguishedName == "" {
		return object
	}
	if !admodel.InternalTopologySameDN(object.DistinguishedName, dn) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return admodel.Object{}
	}
	values, state := object.Attribute("objectclass")
	if state != admodel.AttributePresent {
		read.InternalAdd(admodel.ErrIncompleteResult)
		return object
	}
	for _, value := range values {
		if strings.EqualFold(string(value), class) {
			return object
		}
	}
	read.InternalAdd(admodel.ErrDiscoveryIdentity)
	return admodel.Object{}
}

func internalDiscoveryBytes(read *InternalDirectoryRead, object admodel.Object, name string) []byte {
	values, state := object.Attribute(name)
	if state != admodel.AttributePresent {
		read.InternalAdd(admodel.ErrIncompleteResult)
		return nil
	}
	if len(values) != 1 || len(values[0]) == 0 {
		read.InternalAdd(admodel.ErrInvalidResult)
		return nil
	}
	return values[0]
}

func internalDiscoveryText(read *InternalDirectoryRead, object admodel.Object, name string) string {
	value := internalDiscoveryBytes(read, object, name)
	if len(value) == 0 {
		return ""
	}
	if !admodel.InternalAuthText(string(value)) {
		read.InternalAdd(admodel.ErrInvalidResult)
		return ""
	}
	return string(value)
}

func internalDiscoveryGUID(read *InternalDirectoryRead, object admodel.Object) *string {
	value := internalDiscoveryBytes(read, object, "objectguid")
	if len(value) == 0 {
		return nil
	}
	guid, err := admodel.GUIDFromBytes(value)
	if err != nil || guid == (admodel.GUID{}) {
		read.InternalAdd(admodel.ErrInvalidResult)
		return nil
	}
	text := guid.String()
	return &text
}

func internalDiscoveryGUIDMatches(expected string, actual *string) bool {
	if expected == "" {
		return true
	}
	if actual == nil {
		return false
	}
	first, err := admodel.ParseGUID(expected)
	second, e := admodel.ParseGUID(*actual)
	return err == nil && e == nil && first == second
}

func internalDiscoverySIDMatches(expected string, actual *string) bool {
	if actual == nil {
		return false
	}
	first, err := admodel.ParseSID(expected)
	second, e := admodel.ParseSID(*actual)
	return err == nil && e == nil && bytes.Equal(first.Bytes(), second.Bytes())
}

func internalDiscoveryComputerSID(read *InternalDirectoryRead, object admodel.Object, domain *string) {
	value := internalDiscoveryBytes(read, object, "objectsid")
	if domain == nil || len(value) == 0 {
		return
	}
	_, err := admodel.SIDFromBytes(value)
	parent, e := admodel.ParseSID(*domain)
	if err != nil || e != nil || len(value) != 28 || !admodel.InternalValidDomainSID(parent.Bytes()) {
		read.InternalAdd(admodel.ErrInvalidResult)
		return
	}
	// One additional RID extends the observed domain SID; do not infer domain
	// membership from a hostname suffix, OU name or userAccountControl guess.
	if !bytes.Equal(value[2:24], parent.Bytes()[2:24]) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
}

func internalDiscoverySite(read *InternalDirectoryRead, server, configuration, wanted string, result *admodel.AuthenticatedController) {
	servers, err := admodel.InternalParentDirectoryDN(server)
	if err != nil {
		read.InternalAdd(admodel.ErrInvalidResult)
		return
	}
	site, err := admodel.InternalParentDirectoryDN(servers)
	if err != nil {
		read.InternalAdd(admodel.ErrInvalidResult)
		return
	}
	parent, err := admodel.InternalParentDirectoryDN(site)
	if err != nil || !admodel.InternalTopologySameDN(servers, "CN=Servers,"+site) || !admodel.InternalTopologySameDN(parent, "CN=Sites,"+configuration) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
		return
	}
	object := internalDiscoveryOne(read, site, "site", []string{"name", "objectClass"})
	name := internalDiscoveryText(read, object, "name")
	if name != "" {
		result.SiteName = &name
	}
	if name != "" && !strings.EqualFold(name, wanted) {
		read.InternalAdd(admodel.ErrDiscoveryIdentity)
	}
}
