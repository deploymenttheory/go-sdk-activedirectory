package activedirectory

import (
	"context"
	"errors"
	"fmt"
)

const (
	wellKnownUsers     = "A9D1CA15768811D1ADED00C04FD8D5CD"
	wellKnownComputers = "AA312825768811D1ADED00C04FD8D5CD"
)

var ErrAccountCreationParent = errors.New("account creation default container is unavailable")

// AccountCreationParentError preserves the naming-context observation used to
// locate a default container. A missing/hidden or partial mapping never selects
// a guessed CN=Users/CN=Computers path. No creation has been submitted.
type AccountCreationParentError struct {
	Observation IdentityResult
	Cause       error
}

func (e *AccountCreationParentError) Error() string {
	return fmt.Sprintf("%v: %v", ErrAccountCreationParent, e.Cause)
}
func (e *AccountCreationParentError) Unwrap() []error {
	return []error{ErrAccountCreationParent, e.Cause}
}

func validateAccountCreationOptions(parent Identity, options ObjectMutationOptions) error {
	if parent.Form() != 0 {
		return validateObjectOptions(parent, options)
	}
	if options.Partition != "" {
		if _, err := parseIdentityDN(options.Partition); err != nil {
			return err
		}
	}
	if err := (SearchOptions{Properties: options.Properties}).Validate(); err != nil {
		return err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

// Called inside the owning workflow's session gate and overall timeout.
// wellKnownObjects uses the protocol GUID text, not objectGUID byte order.
func accountCreationParent(ctx context.Context, session directorySession, config Config, root RootDSE, parent Identity, options ObjectMutationOptions, wellKnown string) (Identity, error) {
	if parent.Form() != 0 {
		return parent, nil
	}
	var observed IdentityResult
	fail := func(err error) (Identity, error) {
		return Identity{}, &AccountCreationParentError{Observation: observed, Cause: err}
	}
	if root.Capabilities().Type == DirectoryUnknown {
		return fail(ErrUnsupportedDirectory)
	}
	if root.Capabilities().Type == DirectoryADDS && (config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269) {
		return fail(ErrObjectWriteTarget)
	}
	partition := options.Partition
	if partition == "" {
		partition = config.Partition
	}
	index, _, err := identityPartition(Identity{}, partition, root)
	if err != nil {
		return fail(err)
	}
	partition = root.NamingContexts[index]
	identity, _ := IdentityByDN(partition) // validated by identityPartition
	observed, err = resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: partition, Properties: []string{"objectGUID", "wellKnownObjects"}})
	if err != nil {
		return fail(err)
	}
	if observed.Object.Values("wellKnownObjects").State != AttributePresent {
		return fail(ErrAttributeUnavailable)
	}
	decoder := rootDSEDecoder{attributes: observed.Object.Attributes}
	containers := wellKnownContainers(&decoder)
	if err := errors.Join(decoder.errors...); err != nil {
		return fail(err)
	}
	dn := containers[wellKnown]
	if dn == "" {
		return fail(ErrAttributeUnavailable)
	}
	parent, err = IdentityByDN(dn)
	if err != nil {
		return fail(err)
	}
	if _, _, err := identityPartition(parent, partition, root); err != nil {
		return fail(err)
	}
	return parent, nil
}
