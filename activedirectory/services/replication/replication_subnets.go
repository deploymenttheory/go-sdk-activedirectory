package replication

import (
	"context"
	"errors"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) ReplicationSubnet(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ResolveIdentityOptions,
) (ReplicationSubnetResult, error) {
	var result admodel.ReplicationSubnetResult
	if err := admodel.InternalTopologyIdentity(identity, options); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			options.Partition,
		)
		if err != nil {
			return err
		}
		options.Partition = configuration
		options.Properties = admodel.InternalTopologySubnetProperties(options.Properties)
		result.Observation, err = admodel.InternalResolveIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			adengine.InternalClientConfig(c.engine()),
			root,
			identity,
			options,
		)
		if err != nil {
			return err
		}
		if err := admodel.InternalTopologyDirectChild(
			*result.Observation.Object,
			"CN=Subnets,CN=Sites,"+configuration,
			"subnet",
		); err != nil {
			return err
		}
		subnet, err := admodel.InternalDecodeReplicationSubnet(*result.Observation.Object)
		result.Subnet = &subnet
		return err
	})
	return result, err
}

func (c *Service) ReplicationSubnets(
	ctx context.Context,
	options adshared.SearchOptions,
) (ReplicationSubnetsResult, error) {
	var result admodel.ReplicationSubnetsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	err := adengine.InternalClientRead(c.engine(), ctx, func(ctx context.Context) error {
		root, err := admodel.InternalReadIdentityRoot(
			ctx,
			adengine.InternalClientSession(c.engine()),
		)
		if err != nil {
			return err
		}
		configuration, err := admodel.InternalTopologyConfiguration(
			root,
			adengine.InternalClientConfig(c.engine()),
			"",
		)
		if err != nil {
			return err
		}
		query, err := admodel.InternalTopologySearch(
			options,
			"CN=Subnets,CN=Sites,"+configuration,
			"subnet",
		)
		if err != nil {
			return err
		}
		query.Properties = admodel.InternalTopologySubnetProperties(options.Properties)
		result.Observation, err = admodel.InternalSearchIdentitySession(
			ctx,
			adengine.InternalClientSession(c.engine()),
			query,
		)
		for _, object := range result.Observation.Objects {
			subnet, e := admodel.InternalDecodeReplicationSubnet(object)
			result.Subnets = append(result.Subnets, subnet)
			err = errors.Join(
				err,
				e,
				admodel.InternalTopologyDirectChild(object, query.Base, "subnet"),
			)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}

func (c *Service) CreateReplicationSubnet(
	ctx context.Context,
	request CreateReplicationSubnetRequest,
) (ReplicationSubnetMutationResult, error) {
	var result admodel.ReplicationSubnetMutationResult
	if err := admodel.InternalValidateReplicationSubnet(request.Prefix); err != nil {
		return result, err
	}
	if request.Options.ExpectedVersion != nil {
		return result, admodel.ErrObjectControlUnsupported
	}
	changes := append(
		admodel.InternalTopologyTextChange("description", request.Description),
		admodel.InternalTopologyTextChange("location", request.Location)...)
	for _, change := range changes {
		if !admodel.InternalValidDirectoryText(string(change.Values[0].Bytes())) {
			return result, admodel.ErrInvalidValue
		}
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err := internalServiceTopologyMutationRoot(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	attrs := map[string][]admodel.RawValue{}
	for _, change := range changes {
		attrs[change.Attribute] = change.Values
	}
	if request.Site != nil {
		result.Site, err = internalServiceTopologyLinkedSite(
			c,
			ctx,
			*request.Site,
			options.Partition,
		)
		if err != nil {
			return result, err
		}
		attrs["siteObject"] = []admodel.RawValue{
			admodel.NewRawValue([]byte(result.Site.Object.DistinguishedName)),
		}
	}
	parent, _ := admodel.IdentityByDN("CN=Subnets,CN=Sites," + options.Partition)
	options.Properties = admodel.InternalTopologySubnetProperties(options.Properties)
	mutation, err := c.engine().
		CreateObject(ctx, admodel.CreateObjectRequest{Parent: parent, Class: "subnet", Name: request.Prefix.String(), Attributes: attrs, Options: options})
	return admodel.InternalSubnetMutationProjection(&result, mutation, err)
}

func (c *Service) UpdateReplicationSubnet(
	ctx context.Context,
	request UpdateReplicationSubnetRequest,
) (ReplicationSubnetMutationResult, error) {
	var result admodel.ReplicationSubnetMutationResult
	if err := admodel.InternalTopologyMutationInput(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.Site != nil && request.ClearSite {
		return result, admodel.ErrReplicationTopology
	}
	for _, text := range []*string{request.Description, request.Location} {
		if text != nil && !admodel.InternalValidDirectoryText(*text) {
			return result, admodel.ErrInvalidValue
		}
	}
	if len(request.Changes) > 0 {
		if _, err := admodel.InternalTopologyValidateChanges(
			request.Changes,
			[]string{"siteObject", "cn"},
		); err != nil {
			return result, err
		}
	}
	changes := append(
		admodel.InternalTopologyTextChange("description", request.Description),
		admodel.InternalTopologyTextChange("location", request.Location)...)
	changes = append(changes, request.Changes...)
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err := internalServiceTopologyMutationRoot(c, ctx, request.Options)
	if err != nil {
		return result, err
	}
	if request.Site != nil {
		result.Site, err = internalServiceTopologyLinkedSite(
			c,
			ctx,
			*request.Site,
			options.Partition,
		)
		if err != nil {
			return result, err
		}
		dn := result.Site.Object.DistinguishedName
		changes = append(changes, admodel.InternalTopologyTextChange("siteObject", &dn)...)
	} else if request.ClearSite {
		changes = append(
			changes,
			admodel.AttributeChange{Attribute: "siteObject", Kind: admodel.AttributeClear},
		)
	}
	mods, err := admodel.InternalObjectChanges(changes)
	if err != nil {
		return result, err
	}
	mutation, err := internalServiceTopologyModify(
		c,
		ctx,
		request.Identity,
		options,
		"CN=Subnets,CN=Sites,"+options.Partition,
		"subnet",
		admodel.InternalTopologySubnetProperties(nil),
		func(admodel.Object) ([]admodel.InternalLdapAttributeModification, error) { return mods, nil },
	)
	return admodel.InternalSubnetMutationProjection(&result, mutation, err)
}

func (c *Service) DeleteReplicationSubnet(
	ctx context.Context,
	identity adshared.Identity,
	options adshared.ObjectMutationOptions,
) (adshared.ObjectMutationResult, error) {
	if err := admodel.InternalTopologyMutationInput(identity, options); err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	ctx, cancel, err := adengine.InternalTopologyMutationContext(ctx, c.engine())
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	defer cancel()
	_, options, err = internalServiceTopologyMutationRoot(c, ctx, options)
	if err != nil {
		return admodel.ObjectMutationResult{}, err
	}
	return internalServiceTopologyDelete(c,
		ctx,
		identity,
		options,
		"CN=Subnets,CN=Sites,"+options.Partition,
		"subnet",
	)
}
