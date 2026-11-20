package model

// InternalAccountLDSChanges prepares independent LDS Boolean attributes and the existing never-expire observation without submitting writes.
func InternalAccountLDSChanges(object Object, patch AccountControlPatch) (writes, verification []InternalLdapAttributeModification, neverExpires bool, err error) {
	for _, field := range InternalAccountFlagFields(patch) {
		if field.InternalValue == nil {
			continue
		}
		next := *field.InternalValue != field.InternalInverse
		text := []byte("FALSE")
		if next {
			text = []byte("TRUE")
		}
		// Each LDS option owns a separate boolean attribute, so assignment
		// cannot overwrite unrelated flag bits. Omission may be unset or
		// hidden: write the requested value without inventing an old false.
		unchanged := false
		oldValues := object.Values(field.InternalLdsAttribute)
		if oldValues.State == AttributePresent {
			old, readErr := oldValues.Single()
			if readErr != nil {
				return nil, nil, false, readErr
			}
			value, readErr := old.Bool()
			if readErr != nil {
				return nil, nil, false, readErr
			}
			unchanged = value == next
		}
		if !unchanged {
			writes = append(
				writes,
				InternalAccountValueVerification(field.InternalLdsAttribute, text),
			)
		}
		verification = append(
			verification,
			InternalAccountValueVerification(field.InternalLdsAttribute, text),
		)
	}
	if patch.ChangePasswordAtLogon != nil && *patch.ChangePasswordAtLogon {
		if patch.PasswordNeverExpires != nil {
			neverExpires = *patch.PasswordNeverExpires
		} else {
			value, readErr := object.Values("msDS-UserDontExpirePassword").Single()
			if readErr != nil {
				return nil, nil, false, readErr
			}
			neverExpires, readErr = value.Bool()
			if readErr != nil {
				return nil, nil, false, readErr
			}
		}
	}
	return writes, verification, neverExpires, nil
}
