package activedirectory

import (
	"context"
	"errors"
	"net/netip"
	"slices"
)

type ReplicationSubnet struct {
	Raw                                 Object
	GUID                                *GUID
	Name, Description, Location, SiteDN *string
	Prefix                              *netip.Prefix
}
type ReplicationSubnetResult struct {
	Subnet      *ReplicationSubnet
	Observation IdentityResult
}
type ReplicationSubnetsResult struct {
	Subnets     []ReplicationSubnet
	Observation SearchResult
}
type ReplicationSubnetMutationResult struct {
	Subnet   *ReplicationSubnet
	Mutation ObjectMutationResult
	Site     IdentityResult
}
type CreateReplicationSubnetRequest struct {
	Prefix                netip.Prefix
	Site                  *Identity
	Description, Location *string
	Options               ObjectMutationOptions
}
type UpdateReplicationSubnetRequest struct {
	Identity              Identity
	Site                  *Identity
	ClearSite             bool
	Description, Location *string
	Changes               []AttributeChange
	Options               ObjectMutationOptions
}

func validateReplicationSubnet(prefix netip.Prefix) error {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix != prefix.Masked() {
		return ErrInvalidReplicationSubnet
	}
	return nil
}
func topologySubnetProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "description", "location", "siteObject")
}
func decodeReplicationSubnet(object Object) (ReplicationSubnet, error) {
	result := ReplicationSubnet{Raw: object}
	if err := topologyClass(object, "subnet"); err != nil {
		return result, err
	}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	result.Location = d.text("location")
	result.SiteDN = d.text("siteObject")
	guid, err := topologyGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	if result.Name != nil {
		prefix, e := netip.ParsePrefix(*result.Name)
		if e == nil {
			e = validateReplicationSubnet(prefix)
		}
		if e == nil {
			result.Prefix = &prefix
		}
		err = errors.Join(err, e)
	}
	return result, errors.Join(err, errors.Join(d.errors...))
}
func (c *Client) ReplicationSubnet(ctx context.Context, identity Identity, options ResolveIdentityOptions) (ReplicationSubnetResult, error) {
	var result ReplicationSubnetResult
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
		options.Properties = topologySubnetProperties(options.Properties)
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		if err := topologyDirectChild(*result.Observation.Object, "CN=Subnets,CN=Sites,"+configuration, "subnet"); err != nil {
			return err
		}
		subnet, err := decodeReplicationSubnet(*result.Observation.Object)
		result.Subnet = &subnet
		return err
	})
	return result, err
}
func (c *Client) ReplicationSubnets(ctx context.Context, options SearchOptions) (ReplicationSubnetsResult, error) {
	var result ReplicationSubnetsResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := topologyConfiguration(root, c.config, "")
		if err != nil {
			return err
		}
		query, err := topologySearch(options, "CN=Subnets,CN=Sites,"+configuration, "subnet")
		if err != nil {
			return err
		}
		query.Properties = topologySubnetProperties(options.Properties)
		result.Observation, err = searchIdentitySession(ctx, c.session, query)
		for _, object := range result.Observation.Objects {
			subnet, e := decodeReplicationSubnet(object)
			result.Subnets = append(result.Subnets, subnet)
			err = errors.Join(err, e, topologyDirectChild(object, query.Base, "subnet"))
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
func subnetMutationProjection(result *ReplicationSubnetMutationResult, mutation ObjectMutationResult, err error) (ReplicationSubnetMutationResult, error) {
	result.Mutation = mutation
	if mutation.After != nil {
		subnet, e := decodeReplicationSubnet(*mutation.After)
		result.Subnet = &subnet
		err = errors.Join(err, e)
	}
	return *result, err
}
func (c *Client) CreateReplicationSubnet(ctx context.Context, request CreateReplicationSubnetRequest) (ReplicationSubnetMutationResult, error) {
	var result ReplicationSubnetMutationResult
	if err := validateReplicationSubnet(request.Prefix); err != nil {
		return result, err
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	changes := append(topologyTextChange("description", request.Description), topologyTextChange("location", request.Location)...)
	for _, change := range changes {
		if !validDirectoryText(string(change.Values[0].Bytes())) {
			return result, ErrInvalidValue
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
	attrs := map[string][]RawValue{}
	for _, change := range changes {
		attrs[change.Attribute] = change.Values
	}
	if request.Site != nil {
		result.Site, err = c.topologyLinkedSite(ctx, *request.Site, options.Partition)
		if err != nil {
			return result, err
		}
		attrs["siteObject"] = []RawValue{NewRawValue([]byte(result.Site.Object.DistinguishedName))}
	}
	parent, _ := IdentityByDN("CN=Subnets,CN=Sites," + options.Partition)
	options.Properties = topologySubnetProperties(options.Properties)
	mutation, err := c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: "subnet", Name: request.Prefix.String(), Attributes: attrs, Options: options})
	return subnetMutationProjection(&result, mutation, err)
}
func (c *Client) UpdateReplicationSubnet(ctx context.Context, request UpdateReplicationSubnetRequest) (ReplicationSubnetMutationResult, error) {
	var result ReplicationSubnetMutationResult
	if err := topologyMutationInput(request.Identity, request.Options); err != nil {
		return result, err
	}
	if request.Site != nil && request.ClearSite {
		return result, ErrReplicationTopology
	}
	for _, text := range []*string{request.Description, request.Location} {
		if text != nil && !validDirectoryText(*text) {
			return result, ErrInvalidValue
		}
	}
	if len(request.Changes) > 0 {
		if _, err := topologyValidateChanges(request.Changes, []string{"siteObject", "cn"}); err != nil {
			return result, err
		}
	}
	changes := append(topologyTextChange("description", request.Description), topologyTextChange("location", request.Location)...)
	changes = append(changes, request.Changes...)
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return result, err
	}
	defer cancel()
	_, options, err := c.topologyMutationRoot(ctx, request.Options)
	if err != nil {
		return result, err
	}
	if request.Site != nil {
		result.Site, err = c.topologyLinkedSite(ctx, *request.Site, options.Partition)
		if err != nil {
			return result, err
		}
		dn := result.Site.Object.DistinguishedName
		changes = append(changes, topologyTextChange("siteObject", &dn)...)
	} else if request.ClearSite {
		changes = append(changes, AttributeChange{Attribute: "siteObject", Kind: AttributeClear})
	}
	mods, err := objectChanges(changes)
	if err != nil {
		return result, err
	}
	mutation, err := c.topologyModify(ctx, request.Identity, options, "CN=Subnets,CN=Sites,"+options.Partition, "subnet", topologySubnetProperties(nil), func(Object) ([]ldapAttributeModification, error) { return mods, nil })
	return subnetMutationProjection(&result, mutation, err)
}
func (c *Client) DeleteReplicationSubnet(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	if err := topologyMutationInput(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, err := topologyMutationContext(ctx, c)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	_, options, err = c.topologyMutationRoot(ctx, options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	return c.topologyDelete(ctx, identity, options, "CN=Subnets,CN=Sites,"+options.Partition, "subnet")
}
