package activedirectory

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

func replicationConnectionParent(object Object, configuration string) (string, error) {
	if err := topologyClass(object, "nTDSConnection"); err != nil {
		return "", err
	}
	parent, err := parentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return "", err
	}
	server, err := parentDirectoryDN(parent)
	if err != nil {
		return "", err
	}
	if !topologySameDN(parent, "CN=NTDS Settings,"+server) {
		return "", ErrReplicationTopology
	}
	_, err = topologyServerSiteDN(Object{DistinguishedName: server, Attributes: map[string][][]byte{"objectclass": {[]byte("server")}}}, configuration)
	return parent, err
}
func decodeReplicationConnection(object Object, configuration string) (ReplicationConnection, error) {
	result := ReplicationConnection{Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	result.FromServerDN = d.text("fromServer")
	result.TransportDN = d.text("transportType")
	result.Enabled = decodeScalar(&d, "enabledConnection", func(text string) (bool, error) {
		if strings.EqualFold(text, "TRUE") {
			return true, nil
		}
		if strings.EqualFold(text, "FALSE") {
			return false, nil
		}
		return false, ErrInvalidResult
	})
	if flags := decodeScalar(&d, "options", parseDirectoryMask); flags != nil {
		value := ReplicationConnectionOptions(*flags)
		result.Options = &value
	}
	guid, e := topologyGUID(object)
	if e == nil {
		result.GUID = &guid
	}
	parent, pe := replicationConnectionParent(object, configuration)
	result.DestinationDSADN = parent
	schedule, se := replicationScheduleValue(object)
	result.Schedule = schedule
	return result, errors.Join(e, pe, se, errors.Join(d.errors...))
}
func (c *Client) ReplicationConnection(ctx context.Context, identity Identity, options ResolveIdentityOptions) (ReplicationConnectionResult, error) {
	var result ReplicationConnectionResult
	if err := topologyIdentity(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		options.Partition = configuration
		options.Properties = replicationConnectionProperties(options.Properties)
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		value, err := decodeReplicationConnection(*result.Observation.Object, configuration)
		result.Connection = &value
		return err
	})
	return result, err
}

// ReplicationConnections searches below Sites by default. An explicit base must
// remain below that container. Raw and typed filters retain their usual rules.
func (c *Client) ReplicationConnections(ctx context.Context, options SearchOptions) (ReplicationConnectionsResult, error) {
	var result ReplicationConnectionsResult
	normalized, err := options.normalized()
	if err != nil {
		return result, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, "")
		if err != nil {
			return err
		}
		parent := "CN=Sites," + configuration
		if normalized.Base == "" {
			normalized.Base = parent
			normalized.Scope = ScopeSubtree
		}
		base, e := parseIdentityDN(normalized.Base)
		scope, se := parseIdentityDN(parent)
		if e != nil || se != nil || len(base) < len(scope) || !sameIdentityDN(base[len(base)-len(scope):], scope) {
			return ErrIdentityScope
		}
		normalized.Filter = "(&(objectClass=nTDSConnection)" + normalized.Filter + ")"
		normalized.Properties = replicationConnectionProperties(options.Properties)
		result.Observation, err = searchIdentitySession(ctx, c.session, normalized)
		for _, object := range result.Observation.Objects {
			value, e := decodeReplicationConnection(object, configuration)
			result.Connections = append(result.Connections, value)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
func replicationConnectionSource(ctx context.Context, session directorySession, config Config, root RootDSE, identity Identity, configuration string, result *ReplicationConnectionMutationResult) (string, error) {
	var err error
	result.Source, err = resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: configuration, Properties: []string{"objectGUID", "objectClass"}})
	if err != nil {
		return "", err
	}
	object := *result.Source.Object
	if topologyClass(object, "nTDSDSA") == nil {
		serverDN, e := parentDirectoryDN(object.DistinguishedName)
		if e != nil {
			return "", e
		}
		if !topologySameDN(object.DistinguishedName, "CN=NTDS Settings,"+serverDN) {
			return "", ErrReplicationTopology
		}
		server, e := topologyResolveDN(ctx, session, config, root, serverDN, configuration, []string{"objectClass"})
		if e != nil {
			return "", e
		}
		if _, e = topologyServerSiteDN(*server.Object, configuration); e != nil {
			return "", e
		}
		result.SourceSettings = result.Source
		return object.DistinguishedName, nil
	}
	if _, err := topologyServerSiteDN(object, configuration); err != nil {
		return "", err
	}
	dn := "CN=NTDS Settings," + object.DistinguishedName
	result.SourceSettings, err = topologyResolveDN(ctx, session, config, root, dn, configuration, []string{"objectGUID", "objectClass"})
	if err != nil {
		return "", err
	}
	if err := topologyDirectChild(*result.SourceSettings.Object, object.DistinguishedName, "nTDSDSA"); err != nil {
		return "", err
	}
	return result.SourceSettings.Object.DistinguishedName, nil
}
func (c *Client) UpdateReplicationConnection(ctx context.Context, request UpdateReplicationConnectionRequest) (ReplicationConnectionMutationResult, error) {
	var result ReplicationConnectionMutationResult
	if err := topologyMutationInput(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.ReplicateFromDirectoryServer != nil {
		if err := topologyIdentity(*request.ReplicateFromDirectoryServer, ResolveIdentityOptions{}); err != nil {
			return result, err
		}
	}
	const known = uint32(0x8000007f)
	if request.SetOptions&request.ClearOptions != 0 || uint32(request.SetOptions|request.ClearOptions)&^known != 0 {
		return result, ErrReplicationTopology
	}
	if len(request.Changes) > 0 {
		if _, err := topologyValidateChanges(request.Changes, replicationLinkManaged()); err != nil {
			return result, err
		}
	}
	changes, err := replicationLinkValues(nil, nil, request.Schedule, request.ClearSchedule)
	if err != nil {
		return result, err
	}
	changes = append(changes, topologyTextChange("description", request.Description)...)
	changes = append(changes, request.Changes...)
	if request.Enabled != nil {
		text := "FALSE"
		if *request.Enabled {
			text = "TRUE"
		}
		changes = append(changes, topologyTextChange("enabledConnection", &text)...)
	}
	var mods []ldapAttributeModification
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err := c.topologyMutationRoot(ctx, request.Options)
	if err != nil {
		return result, err
	}
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: replicationConnectionProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		configuration, err := topologyConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		destination, err := replicationConnectionParent(*observed.Object, configuration)
		if err != nil {
			return err
		}
		if request.ReplicateFromDirectoryServer != nil {
			source, err := replicationConnectionSource(ctx, session, c.config, root, *request.ReplicateFromDirectoryServer, configuration, &result)
			if err != nil {
				return err
			}
			if topologySameDN(source, destination) {
				return ErrReplicationTopology
			}
			mods = append(mods, ldapAttributeModification{operation: 2, attribute: "fromServer", values: [][]byte{[]byte(source)}})
		}
		if request.Transport != nil {
			dn, err := replicationTransportParent(root, c.config, configuration, *request.Transport)
			if err != nil {
				return err
			}
			result.Transport, err = topologyResolveDN(ctx, session, c.config, root, dn, configuration, []string{"objectClass"})
			if err != nil {
				return err
			}
			if err := topologyClass(*result.Transport.Object, "interSiteTransport"); err != nil {
				return err
			}
			mods = append(mods, ldapAttributeModification{operation: 2, attribute: "transportType", values: [][]byte{[]byte(result.Transport.Object.DistinguishedName)}})
		}
		flags, err := replicationOptionsMods(*observed.Object, uint32(request.SetOptions), uint32(request.ClearOptions), known)
		if err != nil {
			return err
		}
		mods = append(mods, flags...)
		if len(mods) == 0 {
			if options.ExpectedVersion != nil {
				return ErrObjectControlUnsupported
			}
			mutation.After = mutation.Before
			mutation.ReadbackComplete = true
			mutation.Verified = true
			return nil
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		readOptions := options
		readOptions.Properties = replicationConnectionProperties(readOptions.Properties)
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, mods), false); err != nil {
			return err
		}
		return verifyObjectWrite(mutation, mods, "")
	})
	if result.Mutation.After != nil {
		value, e := decodeReplicationConnection(*result.Mutation.After, options.Partition)
		result.Connection = &value
		err = errors.Join(err, e)
	}
	return result, err
}
