package model

// InternalAggregateObjectMutations summarizes independent requests without
// inventing a shared object identity or a single atomic LDAP acknowledgement.
// Exact identities, observations and failures remain on the individual results.
func InternalAggregateObjectMutations(mutations []ObjectMutationResult, complete bool) ObjectMutationResult {
	result := ObjectMutationResult{Verified: complete && len(mutations) > 0, ReadbackComplete: complete && len(mutations) > 0}
	var accepted, rejected, uncertain, sourceSet, sourceMixed, partitionSet, partitionMixed bool
	for _, mutation := range mutations {
		accepted = accepted || mutation.State == ObjectWriteAccepted
		rejected = rejected || mutation.State == ObjectWriteRejected
		uncertain = uncertain || mutation.State == ObjectWriteUncertain
		result.Verified = result.Verified && mutation.Verified
		result.ReadbackComplete = result.ReadbackComplete && mutation.ReadbackComplete
		result.PartialEffectsPossible = result.PartialEffectsPossible || mutation.PartialEffectsPossible
		if mutation.Source.Host != "" {
			if !sourceSet {
				result.Source, sourceSet = mutation.Source, true
			} else if result.Source != mutation.Source {
				sourceMixed = true
			}
		}
		if mutation.Partition != "" {
			if !partitionSet {
				result.Partition, partitionSet = mutation.Partition, true
			} else if result.Partition != mutation.Partition {
				partitionMixed = true
			}
		}
	}
	switch {
	case uncertain:
		result.State = ObjectWriteUncertain
	case accepted:
		result.State = ObjectWriteAccepted
	case rejected:
		result.State = ObjectWriteRejected
	}
	result.PartialEffectsPossible = result.PartialEffectsPossible || uncertain || (!complete && accepted)
	if sourceMixed {
		result.Source = Endpoint{}
	}
	if partitionMixed {
		result.Partition = ""
	}
	return result
}
