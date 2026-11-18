package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func internalReadReplicationServiceIdentity(
	ctx context.Context, client *Client, config admodel.Config, root admodel.RootDSE, principals admodel.ReplicationServicePrincipals,
) (identity admodel.InternalReplicationServiceIdentity, err error) {
	if root.DNSHostName == nil || root.DSServiceName == nil || root.ServerName == nil || root.RootDomainNamingContext == nil ||
		!strings.EqualFold(strings.TrimSuffix(*root.DNSHostName, "."), strings.TrimSuffix(config.Endpoint.Host, ".")) {
		return identity, admodel.ErrIncompleteResult
	}
	parent, err := admodel.InternalParentDirectoryDN(*root.DSServiceName)
	if err != nil || !admodel.InternalTopologySameDN(parent, *root.ServerName) {
		return identity, errors.Join(admodel.ErrInvalidResult, err)
	}
	rawGUID, err := InternalReplicationInstanceGUID(ctx, client, root)
	if err != nil {
		return identity, err
	}
	identity.DSA, err = admodel.GUIDFromBytes(rawGUID)
	if err != nil || identity.DSA == [16]byte{} {
		return identity, errors.Join(admodel.ErrInvalidResult, err)
	}
	identity.ForestDNS, err = internalReplicationForestDNS(*root.RootDomainNamingContext)
	if err != nil {
		return identity, err
	}
	server, err := internalReplicationIdentityObject(ctx, client, *root.ServerName, "server", []string{"serverReference", "dNSHostName"})
	if err != nil {
		return identity, err
	}
	reference, ok := internalReplicationIdentityText(server, "serverreference")
	if !ok {
		return identity, admodel.ErrIncompleteResult
	}
	computer, err := internalReplicationIdentityObject(ctx, client, reference, "computer", []string{"dNSHostName"})
	if err != nil {
		return identity, err
	}
	host, ok := internalReplicationIdentityText(computer, "dnshostname")
	if !ok || !strings.EqualFold(host, strings.TrimSuffix(config.Endpoint.Host, ".")) {
		return identity, admodel.ErrInvalidResult
	}
	identity.RegisteredSPNs, err = internalReplicationServicePrincipals(ctx, client, reference)
	if err != nil {
		return identity, err
	}
	if err = internalValidateReplicationServiceIdentity(config, root, principals, identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func internalValidateReplicationServiceIdentity(
	config admodel.Config,
	root admodel.RootDSE,
	p admodel.ReplicationServicePrincipals,
	identity admodel.InternalReplicationServiceIdentity,
) error {
	if root.Capabilities().Type != admodel.DirectoryADDS || root.DNSHostName == nil || config.Kerberos == nil ||
		!strings.EqualFold(*root.DNSHostName, strings.TrimSuffix(config.Endpoint.Host, ".")) || p.LDAP != config.Kerberos.SPN {
		return admodel.ErrInvalidConfig
	}
	if root.RootDomainNamingContext == nil {
		return admodel.ErrIncompleteResult
	}
	rootForest, err := internalReplicationForestDNS(*root.RootDomainNamingContext)
	if err != nil || !strings.EqualFold(rootForest, identity.ForestDNS) {
		return errors.Join(admodel.ErrInvalidResult, err)
	}
	if err := admodel.InternalReplicationPrincipalsValidate(map[string]admodel.ReplicationServicePrincipals{config.Endpoint.Host: p}); err != nil {
		return err
	}
	dsa, forest, err := admodel.InternalReplicationEPMIdentity(p.EndpointMapper)
	if err != nil || dsa != identity.DSA || !strings.EqualFold(forest, identity.ForestDNS) || p.DRS == "" {
		return errors.Join(admodel.ErrInvalidConfig, err)
	}
	for _, principal := range []string{p.LDAP, p.EndpointMapper, p.DRS} {
		found := false
		for _, registered := range identity.RegisteredSPNs {
			if strings.EqualFold(registered, principal) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: selected service principal is not registered on the authenticated DC computer", admodel.ErrInvalidResult)
		}
	}
	return nil
}

func internalReplicationIdentityObject(ctx context.Context, client *Client, dn, objectClass string, properties []string) (admodel.Object, error) {
	result, err := client.Search(ctx, admodel.SearchOptions{Base: dn, Scope: admodel.ScopeBase, Filter: "(objectClass=" + objectClass + ")", Properties: properties})
	if err != nil {
		return admodel.Object{}, err
	}
	if !result.Complete || len(result.Objects) != 1 {
		return admodel.Object{}, admodel.ErrIncompleteResult
	}
	if !admodel.InternalTopologySameDN(result.Objects[0].DistinguishedName, dn) {
		return admodel.Object{}, admodel.ErrInvalidResult
	}
	return result.Objects[0], nil
}

func internalReplicationIdentityText(object admodel.Object, attribute string) (string, bool) {
	values, state := object.Attribute(attribute)
	if state != admodel.AttributePresent || len(values) != 1 || !admodel.InternalAuthText(string(values[0])) {
		return "", false
	}
	return string(values[0]), true
}

func internalReplicationForestDNS(dn string) (string, error) {
	parsed, err := admodel.InternalParseIdentityDN(dn)
	if err != nil {
		return "", err
	}
	labels := make([]string, 0, len(parsed))
	for _, rdn := range parsed {
		if len(rdn) != 1 || rdn[0].InternalAttribute != "dc" || rdn[0].InternalBinary || strings.ContainsRune(rdn[0].InternalValue, '.') {
			return "", admodel.ErrInvalidResult
		}
		labels = append(labels, rdn[0].InternalValue)
	}
	forest := strings.Join(labels, ".")
	if !admodel.InternalValidServerHost(forest) {
		return "", admodel.ErrInvalidResult
	}
	return forest, nil
}

func internalReplicationServicePrincipals(ctx context.Context, client *Client, dn string) (values []string, err error) {
	err = InternalClientRead(client, ctx, func(bounded context.Context) error {
		var start uint64
		for {
			property := "serviceprincipalname"
			if start != 0 {
				property = fmt.Sprintf("serviceprincipalname;range=%d-*", start)
			}
			attributes, readErr := client.session.InternalRangedBaseObject(bounded, dn, []string{property})
			raw, next, terminal, rangeErr := admodel.InternalReplicationRange(attributes, "serviceprincipalname", start)
			if readErr != nil || rangeErr != nil {
				return errors.Join(readErr, rangeErr)
			}
			if len(raw) > 1<<20-len(values) {
				return admodel.ErrIncompleteResult
			}
			for _, value := range raw {
				if !admodel.InternalAuthText(string(value)) {
					return admodel.ErrInvalidResult
				}
				values = append(values, string(value))
			}
			if terminal {
				return nil
			}
			if next <= start || next > 1<<20 {
				return admodel.ErrIncompleteResult
			}
			start = next
		}
	})
	return values, err
}
