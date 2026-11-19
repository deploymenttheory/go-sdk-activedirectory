package engine

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// MoveObjectRequest preserves the RDN and GUID using one LDAP ModifyDN.
// TargetParent accepts DN or GUID. Nil Destination means a same-partition move
// on this Client (AD DS or AD LDS). A distinct authenticated Destination opts
// into a cross-domain AD DS move; its credentials are never forwarded.
type MoveObjectRequest struct {
	Identity     admodel.Identity
	TargetParent admodel.Identity
	Destination  *Client
	// DestinationPartition scopes a GUID parent on Destination. Empty follows
	// that client's configured/default partition. Unused for local moves.
	DestinationPartition string
	Options              admodel.ObjectMutationOptions
}

// MoveObject never copy/deletes, rebinds, changes passwords, retries or rolls
// back. Cross-domain server rejection may still have partial effects; inspect
// Mutation even on error. Destination readback verifies GUID and location, not
// passwords or every retained attribute. Preflight is not a transaction.
func (c *Client) MoveObject(
	ctx context.Context,
	request MoveObjectRequest,
) (result admodel.ObjectMoveResult, err error) {
	if err := admodel.InternalValidateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	if err := admodel.InternalValidateObjectOptions(
		request.TargetParent,
		admodel.ObjectMutationOptions{Partition: request.DestinationPartition},
	); err != nil {
		return result, err
	}
	if request.Destination == nil && request.DestinationPartition != "" {
		return result, admodel.ErrInvalidObjectMove
	}
	if c == nil || c.session == nil {
		return result, admodel.ErrClosed
	}
	result.Mutation.Source = c.config.Endpoint
	result.Destination = c.config.Endpoint
	result.CrossDomain = request.Destination != nil
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	var destinationRoot admodel.RootDSE
	var destinationForest admodel.GUID
	if result.CrossDomain {
		destination := request.Destination
		if destination == c {
			return result, admodel.ErrInvalidObjectMove
		}
		if destination.session == nil {
			return result, admodel.ErrClosed
		}
		result.Destination = destination.config.Endpoint
		if !internalMoveAuthenticationAllowed(c.config) {
			return result, admodel.ErrMoveDelegation
		}
		destinationRoot, destinationForest, err = internalMoveDestinationPreflight(bounded, destination, request, &result)
		if err != nil {
			return result, admodel.InternalClassifyObjectWriteError(err)
		}
	}
	err = InternalClientRead(c, bounded, func(ctx context.Context) error {
		return c.internalMoveSourceOperation(ctx, request, destinationRoot, destinationForest, &result)
	})
	if err == nil && result.CrossDomain {
		err = InternalClientRead(request.Destination, bounded, func(ctx context.Context) error {
			return InternalObserveObjectMove(
				ctx,
				request.Destination,
				destinationRoot,
				admodel.InternalObjectWriteProperties(request.Options, nil),
				&result,
			)
		})
		if err != nil {
			err = errors.Join(admodel.ErrObjectReadback, err)
		}
	}
	return result, admodel.InternalClassifyObjectWriteError(err)
}

func internalMoveAuthenticationAllowed(config admodel.Config) bool {
	return config.AllowDelegation && (config.Backend == admodel.BackendNative && config.Authentication == admodel.AuthenticationNegotiate ||
		config.Backend == admodel.BackendPortable && config.Authentication == admodel.AuthenticationKerberos)
}

func InternalMoveRoot(
	ctx context.Context,
	client *Client,
	observation *admodel.DirectoryObservation,
	cross bool,
) (admodel.RootDSE, error) {
	root, err := admodel.InternalReadIdentityRoot(ctx, client.session)
	observation.Source, observation.RootDSE = client.config.Endpoint, root
	if err != nil {
		return root, err
	}
	if root.Capabilities().Type == admodel.DirectoryUnknown ||
		(cross && root.Capabilities().Type != admodel.DirectoryADDS) {
		return root, admodel.ErrUnsupportedDirectory
	}
	if root.Capabilities().Type == admodel.DirectoryADDS &&
		(client.config.Endpoint.Port == 3268 || client.config.Endpoint.Port == 3269) {
		return root, admodel.ErrObjectWriteTarget
	}
	// LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID advertises an RODC.
	if root.Capabilities().Type == admodel.DirectoryADDS &&
		root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return root, admodel.ErrObjectWriteTarget
	}
	if cross {
		if root.DNSHostName == nil || !admodel.InternalValidServerHost(*root.DNSHostName) {
			return root, admodel.ErrInvalidResult
		}
		if _, err := netip.ParseAddr(*root.DNSHostName); err == nil {
			return root, admodel.ErrInvalidResult
		}
		if !strings.EqualFold(
			strings.TrimSuffix(*root.DNSHostName, "."),
			strings.TrimSuffix(client.config.Endpoint.Host, "."),
		) {
			return root, admodel.ErrObjectWriteTarget
		}
	}
	return root, nil
}

// Follow the domain's actual rIDManagerReference (never a guessed CN), as in
// operation-master workflows. fSMORoleOwner must identify this connected DSA.
// The server also checks effective ownership after replication and at dispatch.
func InternalMoveDomainPreflight(
	ctx context.Context,
	client *Client,
	root admodel.RootDSE,
	partition string,
	observation *admodel.DirectoryObservation,
) (admodel.GUID, error) {
	if root.DefaultNamingContext == nil || root.ConfigurationNamingContext == nil ||
		root.DSServiceName == nil ||
		!admodel.InternalSameMoveDN(partition, *root.DefaultNamingContext) {
		return admodel.GUID{}, admodel.ErrMoveForest
	}
	read := func(dn, nc string, properties []string) (*admodel.Object, error) {
		identity, err := admodel.IdentityByDN(dn)
		if err != nil {
			return nil, err
		}
		resolved, err := admodel.InternalResolveIdentitySession(
			ctx,
			client.session,
			client.config,
			root,
			identity,
			admodel.ResolveIdentityOptions{Partition: nc, Properties: properties},
		)
		observation.Objects = append(observation.Objects, resolved.Candidates...)
		return resolved.Object, err
	}
	domain, err := read(
		partition,
		partition,
		[]string{"objectGUID", "objectClass", "instanceType", "rIDManagerReference"},
	)
	if err != nil {
		return admodel.GUID{}, err
	}
	if err := admodel.InternalMoveRequireClass(*domain, "domainDNS"); err != nil {
		return admodel.GUID{}, err
	}
	flags, err := admodel.InternalMoveFlags(*domain, "instanceType", true)
	if err != nil {
		return admodel.GUID{}, err
	}
	if flags&5 != 5 {
		return admodel.GUID{}, admodel.ErrObjectWriteTarget
	}
	managerDN, err := admodel.InternalMoveText(*domain, "rIDManagerReference")
	if err != nil {
		return admodel.GUID{}, err
	}
	manager, err := read(managerDN, partition, []string{"objectClass", "fSMORoleOwner"})
	if err != nil {
		return admodel.GUID{}, err
	}
	if err := admodel.InternalMoveRequireClass(*manager, "rIDManager"); err != nil {
		return admodel.GUID{}, err
	}
	owner, err := admodel.InternalMoveText(*manager, "fSMORoleOwner")
	if err != nil {
		return admodel.GUID{}, err
	}
	if !admodel.InternalSameMoveDN(owner, *root.DSServiceName) {
		return admodel.GUID{}, admodel.ErrMoveRIDMaster
	}
	forest, err := read(
		*root.ConfigurationNamingContext,
		*root.ConfigurationNamingContext,
		[]string{"objectGUID", "objectClass"},
	)
	if err != nil {
		return admodel.GUID{}, err
	}
	if err := admodel.InternalMoveRequireClass(*forest, "configuration"); err != nil {
		return admodel.GUID{}, err
	}
	return admodel.InternalMoveObjectGUID(*forest)
}

func InternalObserveObjectMove(
	ctx context.Context,
	client *Client,
	root admodel.RootDSE,
	properties []string,
	result *admodel.ObjectMoveResult,
) error {
	// The shared observer scopes to Mutation.Partition. Use a copy so the
	// public mutation continues to describe its source naming context.
	observed := result.Mutation
	observed.Partition = result.DestinationPartition
	err := admodel.InternalObserveObjectWrite(
		ctx,
		client.session,
		client.config,
		root,
		admodel.InternalObjectGUIDIdentity(*observed.TargetGUID),
		&observed,
		append(properties, "isDeleted", "isRecycled"),
		false,
	)
	result.Mutation.After, result.Mutation.ReadbackCandidates, result.Mutation.ReadbackComplete = observed.After, observed.ReadbackCandidates, observed.ReadbackComplete
	if err != nil {
		return err
	}
	if !admodel.InternalSameMoveDN(observed.After.DistinguishedName, result.Mutation.TargetDN) {
		return admodel.ErrObjectVerification
	}
	if err := admodel.InternalMoveLiveParent(*observed.After); err != nil {
		return errors.Join(admodel.ErrObjectVerification, err)
	}
	result.Mutation.Verified = true
	return nil
}
