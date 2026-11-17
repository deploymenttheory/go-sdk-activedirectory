package model

import (
	"context"
	"slices"
	"strings"
)

type MoveDirectoryServerRequest struct {
	// Server is an explicit DN/GUID of a configuration server or nTDSDSA object.
	// Computer-account identities are rejected; only the server subtree moves.
	Server, Site Identity
	Options      ObjectMutationOptions
}
type MoveDirectoryServerResult struct {
	Mutation                                                                 ObjectMutationResult
	Input, Server, Settings, SourceSite, DestinationSite, DestinationServers IdentityResult
	SettingsAfter, DestinationSiteAfter                                      IdentityResult
	Before, After                                                            ControllerReplica
	NoChange                                                                 bool
}

func InternalTopologyServerSiteDN(server Object, configuration string) (string, error) {
	if err := InternalTopologyClass(server, "server"); err != nil {
		return "", err
	}
	dn, err := InternalParseIdentityDN(server.DistinguishedName)
	sites, e := InternalParseIdentityDN("CN=Sites," + configuration)
	if err != nil || e != nil || len(dn) != len(sites)+3 ||
		!InternalSameIdentityDN(dn[3:], sites) ||
		len(dn[1]) != 1 ||
		!strings.EqualFold(dn[1][0].InternalAttribute, "cn") ||
		!strings.EqualFold(dn[1][0].InternalValue, "Servers") {
		return "", ErrReplicationTopology
	}
	parent, err := InternalParentDirectoryDN(server.DistinguishedName)
	if err != nil {
		return "", err
	}
	return InternalParentDirectoryDN(parent)
}

func InternalTopologyResolveDN(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	dn, configuration string,
	properties []string,
) (IdentityResult, error) {
	identity, err := IdentityByDN(dn)
	if err != nil {
		return IdentityResult{}, err
	}
	return InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{Partition: configuration, Properties: properties},
	)
}

func InternalTopologySameDN(a, b string) bool {
	first, err := InternalParseIdentityDN(a)
	second, e := InternalParseIdentityDN(b)
	return err == nil && e == nil && InternalSameIdentityDN(first, second)
}

func InternalTopologyServerProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"dnsHostName",
		"serverReference",
	)
}

func InternalTopologyMoveReplica(server, settings Object) ControllerReplica {
	d := InternalRootDSEDecoder{InternalAttributes: server.Attributes}
	return ControllerReplica{
		Server:   server,
		Settings: settings,
		HostName: d.InternalText("dnsHostName"),
	}
}
