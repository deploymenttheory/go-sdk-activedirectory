package model

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// ReplicationRPCProtection preserves measured facts from one diagnostic stage.
// Complete concerns its authenticated protection, independently of query success.
// A refusal can be protected; a successful Kerberos bind alone cannot establish
// HeaderSigned or Confidential. No key material is exposed.
type ReplicationRPCProtection struct {
	Stage                string    `json:"stage"`
	Endpoint             Endpoint  `json:"endpoint"`
	Realm                string    `json:"realm"`
	ServicePrincipal     string    `json:"service_principal"`
	EncryptionType       int32     `json:"encryption_type"`
	CipherBits           uint32    `json:"cipher_bits"`
	ExpiresAt            time.Time `json:"expires_at"`
	MutualAuthentication bool      `json:"mutual_authentication"`
	HeaderSigned         bool      `json:"header_signed"`
	Confidential         bool      `json:"confidential"`
	Complete             bool      `json:"complete"`
}

// ReplicationServicePrincipals specifies exact identities selected by the caller.
// LDAP must agree with Config.Kerberos.SPN for the anchor host. DRS names
// ldap/<selected-host>; EndpointMapper names the registered RPC DSA-GUID/forest
// identity. The SDK verifies all three against authenticated directory data.
// EndpointMapper and DRS may be omitted for an outbound-only LDAP query.
type ReplicationServicePrincipals struct {
	LDAP           string `json:"ldap"`
	EndpointMapper string `json:"endpoint_mapper"`
	DRS            string `json:"drs"`
}

// InternalReplicationServiceIdentity copies facts obtained from the selected
// server's authenticated LDAP connection. It is not a Kerberos/RPC observation.
type InternalReplicationServiceIdentity struct {
	DSA            GUID
	ForestDNS      string
	RegisteredSPNs []string
}

func InternalReplicationHostKey(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func internalReplicationDNS(host string) bool {
	_, ipErr := netip.ParseAddr(host)
	return ipErr != nil && InternalValidServerHost(host)
}

func InternalReplicationPrincipalsValidate(principals map[string]ReplicationServicePrincipals) error {
	seen := make(map[string]bool, len(principals))
	for host, selection := range principals {
		key := InternalReplicationHostKey(host)
		if !internalReplicationDNS(host) || seen[key] || !internalReplicationLDAPPrincipal(selection.LDAP, host) ||
			selection.DRS != "" && !internalReplicationLDAPPrincipal(selection.DRS, host) {
			return fmt.Errorf("%w: invalid or ambiguous per-server replication principal selection", ErrInvalidReplicationQuery)
		}
		seen[key] = true
		if selection.EndpointMapper != "" {
			if _, _, err := InternalReplicationEPMIdentity(selection.EndpointMapper); err != nil {
				return err
			}
		}
	}
	return nil
}

func internalReplicationLDAPPrincipal(principal, host string) bool {
	return strings.HasPrefix(principal, "ldap/") && strings.EqualFold(strings.TrimPrefix(principal, "ldap/"), strings.TrimSuffix(host, "."))
}

// InternalReplicationEPMIdentity parses only the explicit RPC identity. Both
// documented msdcs spellings remain literal; neither is manufactured, rewritten
// or accepted later unless the exact caller-selected SPN is registered on the DC.
func InternalReplicationEPMIdentity(principal string) (GUID, string, error) {
	name := strings.TrimPrefix(principal, "RPC/")
	if !strings.HasPrefix(principal, "RPC/") || len(name) < 37 {
		return GUID{}, "", ErrInvalidReplicationQuery
	}
	guid, err := ParseGUID(name[:36])
	if err != nil || guid == [16]byte{} {
		return GUID{}, "", ErrInvalidReplicationQuery
	}
	forest := strings.TrimPrefix(name[36:], "._msdcs.")
	if forest == name[36:] {
		forest = strings.TrimPrefix(name[36:], ".msdcs.")
	}
	if forest == name[36:] || !internalReplicationDNS(forest) {
		return GUID{}, "", ErrInvalidReplicationQuery
	}
	return guid, forest, nil
}

func InternalReplicationSelectedPrincipals(selection ReplicationSelection, host string) (ReplicationServicePrincipals, bool) {
	key := InternalReplicationHostKey(host)
	for candidate, principal := range selection.ServicePrincipals {
		if InternalReplicationHostKey(candidate) == key {
			return principal, true
		}
	}
	return ReplicationServicePrincipals{}, false
}

// InternalReplicationTargetConfig makes a per-target Kerberos configuration
// without mutating the caller's shared credential selection or inventing an SPN.
func InternalReplicationTargetConfig(config Config, selection ReplicationSelection, endpoint Endpoint, requireRPC bool) (Config, *ReplicationServicePrincipals, error) {
	config.Endpoint = endpoint
	if config.Backend != BackendPortable || selection.ServicePrincipals == nil {
		return config, nil, nil
	}
	principal, ok := InternalReplicationSelectedPrincipals(selection, endpoint.Host)
	if !ok || requireRPC && (principal.EndpointMapper == "" || principal.DRS == "") || config.Kerberos == nil {
		return Config{}, nil, fmt.Errorf("%w: selected replication server has no complete explicit service identities", ErrInvalidConfig)
	}
	kerberos := *config.Kerberos
	kerberos.SPN = principal.LDAP
	config.Kerberos = &kerberos
	return config, &principal, nil
}
