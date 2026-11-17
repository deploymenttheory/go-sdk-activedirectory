package model

import (
	"context"
	"errors"
	"strings"
)

type UpdateReplicationConnectionRequest struct {
	Identity Identity
	// ReplicateFromDirectoryServer is an explicit server or nTDSDSA identity in
	// this configuration. It never selects an account or opens another endpoint.
	ReplicateFromDirectoryServer *Identity
	Transport                    *ReplicationTransport
	Enabled                      *bool
	Description                  *string
	Schedule                     *ReplicationSchedule
	ClearSchedule                bool
	SetOptions, ClearOptions     ReplicationConnectionOptions
	Changes                      []AttributeChange
	Options                      ObjectMutationOptions
}
type ReplicationConnectionMutationResult struct {
	Mutation                          ObjectMutationResult
	Source, SourceSettings, Transport IdentityResult
	Connection                        *ReplicationConnection
}

func InternalReplicationConnectionParent(object Object, configuration string) (string, error) {
	if err := InternalTopologyClass(object, "nTDSConnection"); err != nil {
		return "", err
	}
	parent, err := InternalParentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return "", err
	}
	server, err := InternalParentDirectoryDN(parent)
	if err != nil {
		return "", err
	}
	if !InternalTopologySameDN(parent, "CN=NTDS Settings,"+server) {
		return "", ErrReplicationTopology
	}
	_, err = InternalTopologyServerSiteDN(
		Object{
			DistinguishedName: server,
			Attributes:        map[string][][]byte{"objectclass": {[]byte("server")}},
		},
		configuration,
	)
	return parent, err
}

func InternalDecodeReplicationConnection(
	object Object,
	configuration string,
) (ReplicationConnection, error) {
	result := ReplicationConnection{Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	result.FromServerDN = d.InternalText("fromServer")
	result.TransportDN = d.InternalText("transportType")
	result.Enabled = InternalDecodeScalar(&d, "enabledConnection", func(text string) (bool, error) {
		if strings.EqualFold(text, "TRUE") {
			return true, nil
		}
		if strings.EqualFold(text, "FALSE") {
			return false, nil
		}
		return false, ErrInvalidResult
	})
	if flags := InternalDecodeScalar(&d, "options", InternalParseDirectoryMask); flags != nil {
		value := ReplicationConnectionOptions(*flags)
		result.Options = &value
	}
	guid, e := InternalTopologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	parent, pe := InternalReplicationConnectionParent(object, configuration)
	result.DestinationDSADN = parent
	schedule, se := InternalReplicationScheduleValue(object)
	result.Schedule = schedule
	return result, errors.Join(e, pe, se, errors.Join(d.InternalErrors...))
}

func InternalReplicationConnectionSource(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	identity Identity,
	configuration string,
	result *ReplicationConnectionMutationResult,
) (string, error) {
	var err error
	result.Source, err = InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{
			Partition:  configuration,
			Properties: []string{"objectGUID", "objectClass"},
		},
	)
	if err != nil {
		return "", err
	}
	object := *result.Source.Object
	if InternalTopologyClass(object, "nTDSDSA") == nil {
		serverDN, e := InternalParentDirectoryDN(object.DistinguishedName)
		if e != nil {
			return "", e
		}
		if !InternalTopologySameDN(object.DistinguishedName, "CN=NTDS Settings,"+serverDN) {
			return "", ErrReplicationTopology
		}
		server, e := InternalTopologyResolveDN(
			ctx,
			session,
			config,
			root,
			serverDN,
			configuration,
			[]string{"objectClass"},
		)
		if e != nil {
			return "", e
		}
		if _, e = InternalTopologyServerSiteDN(*server.Object, configuration); e != nil {
			return "", e
		}
		result.SourceSettings = result.Source
		return object.DistinguishedName, nil
	}
	if _, err := InternalTopologyServerSiteDN(object, configuration); err != nil {
		return "", err
	}
	dn := "CN=NTDS Settings," + object.DistinguishedName
	result.SourceSettings, err = InternalTopologyResolveDN(
		ctx,
		session,
		config,
		root,
		dn,
		configuration,
		[]string{"objectGUID", "objectClass"},
	)
	if err != nil {
		return "", err
	}
	if err := InternalTopologyDirectChild(
		*result.SourceSettings.Object,
		object.DistinguishedName,
		"nTDSDSA",
	); err != nil {
		return "", err
	}
	return result.SourceSettings.Object.DistinguishedName, nil
}
