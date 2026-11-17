package replication

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// MoveDirectoryServer moves one server object and all its descendants in the
// same configuration NC. AD maintains linked-DN relationships. No computer
// account, service, connection object or KCC task is separately modified.
func (c *Service) MoveDirectoryServer(
	ctx context.Context,
	request MoveDirectoryServerRequest,
) (MoveDirectoryServerResult, error) {
	var result admodel.MoveDirectoryServerResult
	if err := admodel.InternalTopologyMutationInput(request.Server, request.Options); err != nil {
		return result, err
	}
	if err := admodel.InternalTopologyIdentity(
		request.Site,
		admodel.ResolveIdentityOptions{},
	); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		session, ok := adengine.InternalClientSession(c.engine()).(admodel.InternalLdapWriteSession)
		if !ok {
			return admodel.ErrUnsupported
		}
		root, err := admodel.InternalReadIdentityRoot(ctx, session)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			request.Options.Partition,
		)
		if err != nil {
			return err
		}
		result.Mutation.Source = adengine.InternalClientConfig(c.engine()).Endpoint
		result.Mutation.Partition = configuration
		result.Input, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Server,
			admodel.ResolveIdentityOptions{
				Partition:  configuration,
				Properties: admodel.InternalTopologyServerProperties(request.Options.Properties),
			},
		)
		if err != nil {
			return err
		}
		input := *result.Input.Object
		if admodel.InternalTopologyClass(input, "nTDSDSA") == nil {
			parent, e := admodel.InternalParentDirectoryDN(input.DistinguishedName)
			if e != nil {
				return e
			}
			result.Server, err = admodel.InternalTopologyResolveDN(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				parent,
				configuration,
				admodel.InternalTopologyServerProperties(request.Options.Properties),
			)
			if err != nil {
				return err
			}
			result.Settings = result.Input
		} else if admodel.InternalTopologyClass(input, "server") == nil {
			result.Server = result.Input
			result.Settings, err = admodel.InternalTopologyResolveDN(
				ctx,
				session,
				adengine.InternalClientConfig(c.engine()),
				root,
				"CN=NTDS Settings,"+input.DistinguishedName,
				configuration,
				[]string{"objectGUID", "objectClass", "options", "invocationId"},
			)
			if err != nil {
				return err
			}
		} else {
			return admodel.ErrReplicationTopology
		}
		server, settings := *result.Server.Object, *result.Settings.Object
		sourceDN, err := admodel.InternalTopologyServerSiteDN(server, configuration)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(
			settings,
			server.DistinguishedName,
			"nTDSDSA",
		); err != nil {
			return err
		}
		if !admodel.InternalTopologySameDN(
			settings.DistinguishedName,
			"CN=NTDS Settings,"+server.DistinguishedName,
		) {
			return admodel.ErrReplicationTopology
		}
		serverGUID, err := admodel.InternalTopologyGUID(server)
		if err != nil {
			return err
		}
		settingsGUID, err := admodel.InternalTopologyGUID(settings)
		if err != nil {
			return err
		}
		result.Before = admodel.InternalTopologyMoveReplica(server, settings)
		result.Mutation.Before = &server
		result.Mutation.TargetDN = server.DistinguishedName
		result.Mutation.TargetGUID = &serverGUID
		result.Mutation.PreflightCandidates = result.Server.Candidates
		result.SourceSite, err = admodel.InternalTopologyResolveDN(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			sourceDN,
			configuration,
			admodel.InternalTopologySiteProperties(nil),
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(
			*result.SourceSite.Object,
			"CN=Sites,"+configuration,
			"site",
		); err != nil {
			return err
		}
		result.DestinationSite, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			request.Site,
			admodel.ResolveIdentityOptions{
				Partition:  configuration,
				Properties: admodel.InternalTopologySiteProperties(nil),
			},
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(
			*result.DestinationSite.Object,
			"CN=Sites,"+configuration,
			"site",
		); err != nil {
			return err
		}
		siteGUID, err := admodel.InternalTopologyGUID(*result.DestinationSite.Object)
		if err != nil {
			return err
		}
		destinationDN := result.DestinationSite.Object.DistinguishedName
		result.DestinationServers, err = admodel.InternalTopologyResolveDN(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			"CN=Servers,"+destinationDN,
			configuration,
			[]string{"objectGUID", "objectClass"},
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(
			*result.DestinationServers.Object,
			destinationDN,
			"serversContainer",
		); err != nil {
			return err
		}
		if admodel.InternalTopologySameDN(sourceDN, destinationDN) {
			if request.Options.ExpectedVersion != nil {
				return admodel.ErrObjectControlUnsupported
			}
			result.NoChange = true
			result.After = result.Before
			result.Mutation.After = result.Mutation.Before
			result.Mutation.ReadbackComplete = true
			result.Mutation.Verified = true
			return nil
		}
		controls, err := admodel.InternalObjectWriteControls(
			root,
			adengine.InternalClientConfig(c.engine()).Endpoint,
			request.Options,
			serverGUID,
			false,
		)
		if err != nil {
			return err
		}
		dn, err := admodel.InternalParseIdentityDN(server.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].InternalBinary {
			return admodel.ErrReplicationTopology
		}
		rdn := dn[0][0].InternalAttribute + "=" + admodel.InternalEscapeObjectName(
			dn[0][0].InternalValue,
		)
		write := admodel.InternalLdapWriteRequest{
			InternalOperation:    admodel.InternalLdapWriteRename,
			InternalDn:           admodel.InternalObjectGUIDTarget(serverGUID),
			InternalNewRDN:       rdn,
			InternalNewParent:    result.DestinationServers.Object.DistinguishedName,
			InternalDeleteOldRDN: true,
			InternalControls:     controls,
		}
		if err := admodel.InternalSubmitObjectWrite(
			ctx,
			session,
			write,
			false,
			&result.Mutation,
		); err != nil {
			return err
		}
		if err := admodel.InternalObserveObjectWrite(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			admodel.InternalObjectGUIDIdentity(serverGUID),
			&result.Mutation,
			admodel.InternalTopologyServerProperties(request.Options.Properties),
			false,
		); err != nil {
			return err
		}
		result.SettingsAfter, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			admodel.InternalObjectGUIDIdentity(settingsGUID),
			admodel.ResolveIdentityOptions{
				Partition:  configuration,
				Properties: []string{"objectGUID", "objectClass", "options", "invocationId"},
			},
		)
		if err != nil {
			return errors.Join(admodel.ErrObjectReadback, err)
		}
		result.DestinationSiteAfter, err = admodel.InternalResolveIdentitySession(
			ctx,
			session,
			adengine.InternalClientConfig(c.engine()),
			root,
			admodel.InternalObjectGUIDIdentity(siteGUID),
			admodel.ResolveIdentityOptions{
				Partition:  configuration,
				Properties: admodel.InternalTopologySiteProperties(nil),
			},
		)
		if err != nil {
			return errors.Join(admodel.ErrObjectReadback, err)
		}
		observedSettingsGUID, settingsGUIDErr := admodel.InternalTopologyGUID(
			*result.SettingsAfter.Object,
		)
		observedSiteGUID, siteGUIDErr := admodel.InternalTopologyGUID(
			*result.DestinationSiteAfter.Object,
		)
		if settingsGUIDErr != nil || siteGUIDErr != nil || observedSettingsGUID != settingsGUID ||
			observedSiteGUID != siteGUID {
			return errors.Join(admodel.ErrObjectVerification, settingsGUIDErr, siteGUIDErr)
		}
		if err := admodel.InternalTopologyDirectChild(
			*result.DestinationSiteAfter.Object,
			"CN=Sites,"+configuration,
			"site",
		); err != nil {
			return errors.Join(admodel.ErrObjectVerification, err)
		}
		afterServer, afterSettings := *result.Mutation.After, *result.SettingsAfter.Object
		result.After = admodel.InternalTopologyMoveReplica(afterServer, afterSettings)
		afterSite, e := admodel.InternalTopologyServerSiteDN(afterServer, configuration)
		if e != nil ||
			!admodel.InternalTopologySameDN(
				afterSite,
				result.DestinationSiteAfter.Object.DistinguishedName,
			) ||
			admodel.InternalTopologyDirectChild(
				afterSettings,
				afterServer.DistinguishedName,
				"nTDSDSA",
			) != nil ||
			!admodel.InternalTopologySameDN(
				afterSettings.DistinguishedName,
				"CN=NTDS Settings,"+afterServer.DistinguishedName,
			) {
			return admodel.ErrObjectVerification
		}
		// Preserve the domain computer link in AD DS. AD LDS server objects do
		// not require that link. Omitted AD DS links cannot establish preservation.
		beforeLink, beforeState := server.Attribute("serverReference")
		afterLink, afterState := afterServer.Attribute("serverReference")
		if root.Capabilities().Type == admodel.DirectoryADDS ||
			beforeState == admodel.AttributePresent {
			if beforeState != admodel.AttributePresent || afterState != admodel.AttributePresent ||
				len(beforeLink) != 1 ||
				len(afterLink) != 1 ||
				!admodel.InternalTopologySameDN(string(beforeLink[0]), string(afterLink[0])) {
				return admodel.ErrObjectVerification
			}
		}
		result.Mutation.Verified = true
		return nil
	})
	return result, admodel.InternalClassifyObjectWriteError(err)
}
