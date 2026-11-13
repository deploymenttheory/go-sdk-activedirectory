package activedirectory

import (
	"context"
	"errors"
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

func topologyServerSiteDN(server Object, configuration string) (string, error) {
	if err := topologyClass(server, "server"); err != nil {
		return "", err
	}
	dn, err := parseIdentityDN(server.DistinguishedName)
	sites, e := parseIdentityDN("CN=Sites," + configuration)
	if err != nil || e != nil || len(dn) != len(sites)+3 || !sameIdentityDN(dn[3:], sites) || len(dn[1]) != 1 || !strings.EqualFold(dn[1][0].attribute, "cn") || !strings.EqualFold(dn[1][0].value, "Servers") {
		return "", ErrReplicationTopology
	}
	parent, err := parentDirectoryDN(server.DistinguishedName)
	if err != nil {
		return "", err
	}
	return parentDirectoryDN(parent)
}
func topologyResolveDN(ctx context.Context, session directorySession, config Config, root RootDSE, dn, configuration string, properties []string) (IdentityResult, error) {
	identity, err := IdentityByDN(dn)
	if err != nil {
		return IdentityResult{}, err
	}
	return resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: configuration, Properties: properties})
}
func topologySameDN(a, b string) bool {
	first, err := parseIdentityDN(a)
	second, e := parseIdentityDN(b)
	return err == nil && e == nil && sameIdentityDN(first, second)
}
func topologyServerProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "dnsHostName", "serverReference")
}
func topologyMoveReplica(server, settings Object) ControllerReplica {
	d := rootDSEDecoder{attributes: server.Attributes}
	return ControllerReplica{Server: server, Settings: settings, HostName: d.text("dnsHostName")}
}

// MoveDirectoryServer moves one server object and all its descendants in the
// same configuration NC. AD maintains linked-DN relationships. No computer
// account, service, connection object or KCC task is separately modified.
func (c *Client) MoveDirectoryServer(ctx context.Context, request MoveDirectoryServerRequest) (MoveDirectoryServerResult, error) {
	var result MoveDirectoryServerResult
	if err := topologyMutationInput(request.Server, request.Options); err != nil {
		return result, err
	}
	if err := topologyIdentity(request.Site, ResolveIdentityOptions{}); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		session, ok := c.session.(ldapWriteSession)
		if !ok {
			return ErrUnsupported
		}
		root, err := readIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, request.Options.Partition)
		if err != nil {
			return err
		}
		result.Mutation.Source = c.config.Endpoint
		result.Mutation.Partition = configuration
		result.Input, err = resolveIdentitySession(ctx, session, c.config, root, request.Server, ResolveIdentityOptions{Partition: configuration, Properties: topologyServerProperties(request.Options.Properties)})
		if err != nil {
			return err
		}
		input := *result.Input.Object
		if topologyClass(input, "nTDSDSA") == nil {
			parent, e := parentDirectoryDN(input.DistinguishedName)
			if e != nil {
				return e
			}
			result.Server, err = topologyResolveDN(ctx, session, c.config, root, parent, configuration, topologyServerProperties(request.Options.Properties))
			if err != nil {
				return err
			}
			result.Settings = result.Input
		} else if topologyClass(input, "server") == nil {
			result.Server = result.Input
			result.Settings, err = topologyResolveDN(ctx, session, c.config, root, "CN=NTDS Settings,"+input.DistinguishedName, configuration, []string{"objectGUID", "objectClass", "options", "invocationId"})
			if err != nil {
				return err
			}
		} else {
			return ErrReplicationTopology
		}
		server, settings := *result.Server.Object, *result.Settings.Object
		sourceDN, err := topologyServerSiteDN(server, configuration)
		if err != nil {
			return err
		}
		if err := topologyDirectChild(settings, server.DistinguishedName, "nTDSDSA"); err != nil {
			return err
		}
		if !topologySameDN(settings.DistinguishedName, "CN=NTDS Settings,"+server.DistinguishedName) {
			return ErrReplicationTopology
		}
		serverGUID, err := topologyGUID(server)
		if err != nil {
			return err
		}
		settingsGUID, err := topologyGUID(settings)
		if err != nil {
			return err
		}
		result.Before = topologyMoveReplica(server, settings)
		result.Mutation.Before = &server
		result.Mutation.TargetDN = server.DistinguishedName
		result.Mutation.TargetGUID = &serverGUID
		result.Mutation.PreflightCandidates = result.Server.Candidates
		result.SourceSite, err = topologyResolveDN(ctx, session, c.config, root, sourceDN, configuration, topologySiteProperties(nil))
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*result.SourceSite.Object, "CN=Sites,"+configuration, "site"); err != nil {
			return err
		}
		result.DestinationSite, err = resolveIdentitySession(ctx, session, c.config, root, request.Site, ResolveIdentityOptions{Partition: configuration, Properties: topologySiteProperties(nil)})
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*result.DestinationSite.Object, "CN=Sites,"+configuration, "site"); err != nil {
			return err
		}
		siteGUID, err := topologyGUID(*result.DestinationSite.Object)
		if err != nil {
			return err
		}
		destinationDN := result.DestinationSite.Object.DistinguishedName
		result.DestinationServers, err = topologyResolveDN(ctx, session, c.config, root, "CN=Servers,"+destinationDN, configuration, []string{"objectGUID", "objectClass"})
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*result.DestinationServers.Object, destinationDN, "serversContainer"); err != nil {
			return err
		}
		if topologySameDN(sourceDN, destinationDN) {
			if request.Options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			result.NoChange = true
			result.After = result.Before
			result.Mutation.After = result.Mutation.Before
			result.Mutation.ReadbackComplete = true
			result.Mutation.Verified = true
			return nil
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, request.Options, serverGUID, false)
		if err != nil {
			return err
		}
		dn, err := parseIdentityDN(server.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].binary {
			return ErrReplicationTopology
		}
		rdn := dn[0][0].attribute + "=" + escapeObjectName(dn[0][0].value)
		write := ldapWriteRequest{operation: ldapWriteRename, dn: objectGUIDTarget(serverGUID), newRDN: rdn, newParent: result.DestinationServers.Object.DistinguishedName, deleteOldRDN: true, controls: controls}
		if err := submitObjectWrite(ctx, session, write, false, &result.Mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(serverGUID), &result.Mutation, topologyServerProperties(request.Options.Properties), false); err != nil {
			return err
		}
		result.SettingsAfter, err = resolveIdentitySession(ctx, session, c.config, root, objectGUIDIdentity(settingsGUID), ResolveIdentityOptions{Partition: configuration, Properties: []string{"objectGUID", "objectClass", "options", "invocationId"}})
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		result.DestinationSiteAfter, err = resolveIdentitySession(ctx, session, c.config, root, objectGUIDIdentity(siteGUID), ResolveIdentityOptions{Partition: configuration, Properties: topologySiteProperties(nil)})
		if err != nil {
			return errors.Join(ErrObjectReadback, err)
		}
		observedSettingsGUID, settingsGUIDErr := topologyGUID(*result.SettingsAfter.Object)
		observedSiteGUID, siteGUIDErr := topologyGUID(*result.DestinationSiteAfter.Object)
		if settingsGUIDErr != nil || siteGUIDErr != nil || observedSettingsGUID != settingsGUID || observedSiteGUID != siteGUID {
			return errors.Join(ErrObjectVerification, settingsGUIDErr, siteGUIDErr)
		}
		if err := topologyDirectChild(*result.DestinationSiteAfter.Object, "CN=Sites,"+configuration, "site"); err != nil {
			return errors.Join(ErrObjectVerification, err)
		}
		afterServer, afterSettings := *result.Mutation.After, *result.SettingsAfter.Object
		result.After = topologyMoveReplica(afterServer, afterSettings)
		afterSite, e := topologyServerSiteDN(afterServer, configuration)
		if e != nil || !topologySameDN(afterSite, result.DestinationSiteAfter.Object.DistinguishedName) || topologyDirectChild(afterSettings, afterServer.DistinguishedName, "nTDSDSA") != nil || !topologySameDN(afterSettings.DistinguishedName, "CN=NTDS Settings,"+afterServer.DistinguishedName) {
			return ErrObjectVerification
		}
		// Preserve the domain computer link in AD DS. AD LDS server objects do
		// not require that link. Omitted AD DS links cannot establish preservation.
		beforeLink, beforeState := server.Attribute("serverReference")
		afterLink, afterState := afterServer.Attribute("serverReference")
		if root.Capabilities().Type == DirectoryADDS || beforeState == AttributePresent {
			if beforeState != AttributePresent || afterState != AttributePresent || len(beforeLink) != 1 || len(afterLink) != 1 || !topologySameDN(string(beforeLink[0]), string(afterLink[0])) {
				return ErrObjectVerification
			}
		}
		result.Mutation.Verified = true
		return nil
	})
	return result, classifyObjectWriteError(err)
}
