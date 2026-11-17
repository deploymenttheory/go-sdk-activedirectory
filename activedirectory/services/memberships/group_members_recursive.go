package memberships

import (
	"context"
	"errors"
	"fmt"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adshared "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/shared"
)

func (c *Service) GroupMembers(
	ctx context.Context,
	identity adshared.Identity,
	options GroupMembersOptions,
) (result GroupMembersResult, err error) {
	defer func() {
		result.LimitReached = result.LimitReached || errors.Is(err, admodel.ErrMembershipLimit) ||
			errors.Is(err, admodel.ErrGroupMembershipLimit)
	}()
	limits, err := admodel.InternalNormalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if err := admodel.InternalValidateIdentityOperation(
		identity,
		admodel.InternalMembershipResolveOptions(identity, options.Partition, options.Properties),
	); err != nil {
		return result, err
	}
	if c.engine() == nil || adengine.InternalClientSession(c.engine()) == nil {
		return result, admodel.ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, adengine.InternalClientConfig(c.engine()).Timeout)
	defer cancel()
	home, err := adengine.InternalNewMembershipEndpoint(
		bounded,
		c.engine(),
		identity,
		options.Partition,
		true,
	)
	if err != nil {
		return result, err
	}
	endpoints, err := adengine.InternalMembershipContexts(bounded, home, options.Contexts)
	if err != nil {
		return result, err
	}
	budget := admodel.InternalMembershipBudget{InternalLimits: limits}
	type queuedGroup struct {
		InternalIdentity                admodel.Identity
		InternalEndpoint, InternalDepth int
	}
	queue := []queuedGroup{{InternalIdentity: identity}}
	groups, principals := map[string]bool{}, map[string]int{}
	var failures []error
	for len(queue) > 0 {
		if err := context.Cause(bounded); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		item := queue[0]
		queue = queue[1:]
		if budget.InternalGroups >= limits.MaxGroups || item.InternalDepth > limits.MaxDepth ||
			budget.InternalObjects >= limits.MaxObjects ||
			budget.InternalRanges >= limits.MaxRanges ||
			budget.InternalBytes >= limits.MaxBytes {
			result.LimitReached = true
			return result, errors.Join(append(failures, admodel.ErrMembershipLimit)...)
		}
		e := endpoints[item.InternalEndpoint]
		links, readErr := New(
			e.InternalClient,
		).GroupMemberLinks(bounded, item.InternalIdentity, admodel.GroupMemberLinksOptions{
			Partition: e.InternalPartition,
			MaxValues: limits.MaxObjects - budget.InternalObjects,
			MaxRanges: limits.MaxRanges - budget.InternalRanges,
			MaxBytes:  limits.MaxBytes - budget.InternalBytes,
		})
		result.Groups = append(
			result.Groups,
			admodel.GroupMembershipTraversal{
				Source: adengine.InternalClientConfig(e.InternalClient).Endpoint,
				Depth:  item.InternalDepth,
				Links:  links,
			},
		)
		node := &result.Groups[len(result.Groups)-1]
		budget.InternalGroups++
		for _, r := range links.Ranges {
			budget.InternalRanges++
			if err := budget.InternalAttributes(r.Attributes); err != nil {
				result.LimitReached = true
				return result, errors.Join(readErr, err)
			}
		}
		for _, object := range links.Observation.Candidates {
			if err := budget.InternalObject(object); err != nil {
				result.LimitReached = true
				return result, errors.Join(readErr, err)
			}
		}
		if readErr != nil {
			result.LimitReached = errors.Is(readErr, admodel.ErrGroupMembershipLimit)
			return result, errors.Join(append(failures, readErr)...)
		}
		group, decodeErr := admodel.InternalDecodeMembershipPrincipal(
			*links.Observation.Object,
			adengine.InternalClientConfig(e.InternalClient).Endpoint,
		)
		if decodeErr != nil {
			return result, errors.Join(append(failures, decodeErr)...)
		}
		groups[group.SID.String()] = true
		observations := make([]admodel.MembershipResolution, 0, len(links.Members))
		for _, link := range links.Members {
			if budget.InternalObjects >= limits.MaxObjects {
				result.LimitReached = true
				return result, errors.Join(append(failures, admodel.ErrMembershipLimit)...)
			}
			observation, index := adengine.InternalResolveMembershipLink(
				bounded,
				link.DistinguishedName,
				endpoints,
				options.Properties,
				&budget,
			)
			node.Resolutions = append(node.Resolutions, observation)
			if observation.Error != nil {
				result.Unresolved = append(result.Unresolved, observation)
				failures = append(failures, observation.Error)
				if errors.Is(observation.Error, admodel.ErrMembershipLimit) {
					result.LimitReached = true
					return result, errors.Join(failures...)
				}
				continue
			}
			// The endpoint follows a resolved foreign principal, not its FSP.
			observation.Source = adengine.InternalClientConfig(
				endpoints[index].InternalClient,
			).Endpoint
			observations = append(observations, observation)
		}
		if e.InternalRoot.Capabilities().Type == admodel.DirectoryADDS {
			if rid, domainGroup := admodel.InternalMembershipDomainRID(group.SID); domainGroup {
				if budget.InternalObjects >= limits.MaxObjects {
					result.LimitReached = true
					return result, errors.Join(append(failures, admodel.ErrMembershipLimit)...)
				}
				query := admodel.SearchOptions{
					Base:  e.InternalPartition,
					Scope: admodel.ScopeSubtree,
					TypedFilter: admodel.FilterAnd(
						admodel.FilterPresent("objectSid"),
						admodel.FilterEqual("primaryGroupID", admodel.FilterText(fmt.Sprint(rid))),
					),
					Properties:  admodel.InternalMembershipProperties(options.Properties),
					ResultLimit: limits.MaxObjects - budget.InternalObjects,
				}
				primary, primaryErr := e.InternalSearch(bounded, query)
				node.PrimaryMembers = primary
				for _, object := range primary.Objects {
					if err := budget.InternalObject(object); err != nil {
						result.LimitReached = true
						return result, errors.Join(primaryErr, err)
					}
				}
				if primaryErr != nil || !primary.Complete {
					result.LimitReached = primary.LimitReached
					return result, errors.Join(
						append(failures, primaryErr, admodel.ErrIncompleteResult)...)
				}
				for i := range primary.Objects {
					object := primary.Objects[i]
					sid, present, err := admodel.InternalMembershipPrimarySID(object)
					if err != nil || !present || sid.String() != group.SID.String() {
						return result, errors.Join(
							append(failures, err, admodel.ErrInvalidResult)...)
					}
					observations = append(
						observations,
						admodel.MembershipResolution{
							Source:    adengine.InternalClientConfig(e.InternalClient).Endpoint,
							Reference: object.DistinguishedName,
							Observation: admodel.IdentityResult{
								Source: adengine.InternalClientConfig(
									e.InternalClient,
								).Endpoint,
								Partition:  e.InternalPartition,
								Object:     &object,
								Candidates: []admodel.Object{object},
								Complete:   true,
							},
						},
					)
				}
			}
		}
		for _, observation := range observations {
			object := *observation.Observation.Object
			if values := object.Values(
				"objectSid",
			); values.State != admodel.AttributePresent && !admodel.InternalMembershipHasClass(object, "user") && !admodel.InternalMembershipHasClass(object, "group") &&
				!admodel.InternalMembershipHasClass(object, "foreignSecurityPrincipal") {
				continue
			}
			principal, err := admodel.InternalDecodeMembershipPrincipal(object, observation.Source)
			if err != nil {
				observation.Error = err
				result.Unresolved = append(result.Unresolved, observation)
				failures = append(failures, err)
				continue
			}
			key := principal.SID.String()
			if admodel.InternalMembershipHasClass(object, "group") && options.Recursive {
				if groups[key] {
					continue
				}
				groups[key] = true
				index, err := adengine.InternalMembershipDNEndpoint(
					object.DistinguishedName,
					endpoints,
				)
				if err != nil {
					observation.Error = err
					result.Unresolved = append(result.Unresolved, observation)
					failures = append(failures, err)
					continue
				}
				queue = append(
					queue,
					queuedGroup{
						InternalIdentity: admodel.InternalObjectGUIDIdentity(principal.GUID),
						InternalEndpoint: index,
						InternalDepth:    item.InternalDepth + 1,
					},
				)
				continue
			}
			primary, hasPrimary, _ := admodel.InternalMembershipPrimarySID(object)
			principal.Primary = hasPrimary && primary.String() == group.SID.String()
			if previous, exists := principals[key]; exists {
				result.Members[previous].Primary = result.Members[previous].Primary ||
					principal.Primary
				continue
			}
			principals[key] = len(result.Members)
			result.Members = append(result.Members, principal)
		}
	}
	err = errors.Join(failures...)
	result.Complete = err == nil
	return result, err
}
