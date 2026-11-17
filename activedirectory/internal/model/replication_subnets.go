package model

import (
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

func InternalValidateReplicationSubnet(prefix netip.Prefix) error {
	if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" ||
		prefix != prefix.Masked() {
		return ErrInvalidReplicationSubnet
	}
	return nil
}

func InternalTopologySubnetProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"description",
		"location",
		"siteObject",
	)
}

func InternalDecodeReplicationSubnet(object Object) (ReplicationSubnet, error) {
	result := ReplicationSubnet{Raw: object}
	if err := InternalTopologyClass(object, "subnet"); err != nil {
		return result, err
	}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	result.Location = d.InternalText("location")
	result.SiteDN = d.InternalText("siteObject")
	guid, err := InternalTopologyGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	if result.Name != nil {
		prefix, e := netip.ParsePrefix(*result.Name)
		if e == nil {
			e = InternalValidateReplicationSubnet(prefix)
		}
		if e == nil {
			result.Prefix = &prefix
		}
		err = errors.Join(err, e)
	}
	return result, errors.Join(err, errors.Join(d.InternalErrors...))
}

func InternalSubnetMutationProjection(
	result *ReplicationSubnetMutationResult,
	mutation ObjectMutationResult,
	err error,
) (ReplicationSubnetMutationResult, error) {
	result.Mutation = mutation
	if mutation.After != nil {
		subnet, e := InternalDecodeReplicationSubnet(*mutation.After)
		result.Subnet = &subnet
		err = errors.Join(err, e)
	}
	return *result, err
}
