package activedirectory

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func accountTestEntry(flags Flags32) Object {
	object := objectTestEntry("CN=sample,DC=example")
	object.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("person"), []byte("user")}
	object.Attributes["useraccountcontrol"] = [][]byte{[]byte(flags.LDAPString())}
	object.Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("0")}
	object.Attributes["pwdlastset"] = [][]byte{[]byte("123456")}
	object.Attributes["lockouttime"] = [][]byte{[]byte("0")}
	return object
}

func TestAccountControlStoredFieldsPreserveUnrelatedBits(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		fields := []struct {
			patch   AccountControlPatch
			mask    Flags32
			inverse bool
		}{
			{AccountControlPatch{Enabled: &enabled}, 2, true},
			{AccountControlPatch{HomeDirectoryRequired: &enabled}, 8, false},
			{AccountControlPatch{PasswordNotRequired: &enabled}, 32, false},
			{AccountControlPatch{AllowReversiblePasswordEncryption: &enabled}, 128, false},
			{AccountControlPatch{PasswordNeverExpires: &enabled}, 65536, false},
			{AccountControlPatch{MNSLogonAccount: &enabled}, 131072, false},
			{AccountControlPatch{SmartcardLogonRequired: &enabled}, 262144, false},
			{AccountControlPatch{TrustedForDelegation: &enabled}, 524288, false},
			{AccountControlPatch{AccountNotDelegated: &enabled}, 1048576, false},
			{AccountControlPatch{UseDESKeyOnly: &enabled}, 2097152, false},
			{AccountControlPatch{DoesNotRequirePreAuth: &enabled}, 4194304, false},
			{AccountControlPatch{TrustedToAuthForDelegation: &enabled}, 16777216, false},
		}
		for _, tc := range fields {
			old := Flags32(0x40000200).With(tc.mask, enabled == tc.inverse)
			writes, verify, err := accountControlChanges(accountTestEntry(old), DirectoryADDS, tc.patch)
			if err != nil || len(writes) != 2 || len(verify) != 1 {
				t.Fatal(tc, err, writes, verify)
			}
			next, err := NewRawValue(writes[1].values[0]).Flags32()
			if err != nil || next&^tc.mask != old&^tc.mask || next.Has(tc.mask) != (enabled != tc.inverse) || writes[0].operation != 1 || writes[1].operation != 0 || string(writes[0].values[0]) != old.LDAPString() {
				t.Fatal(tc, writes, next, err)
			}
		}
	}
}

func TestAccountControlComputedStateIsNotStoredFlagsOrTimestamp(t *testing.T) {
	object := accountTestEntry(0x800010 | 0x200)
	object.Attributes["lockouttime"] = [][]byte{[]byte("100")}
	state, err := decodeAccountControl(object, DirectoryADDS)
	if err != nil || state.LockedOut == nil || *state.LockedOut || *state.PasswordExpired || *state.LockoutTime != 100 {
		t.Fatal(state, err)
	}
	delete(object.Attributes, "msds-user-account-control-computed")
	state, err = decodeAccountControl(object, DirectoryADDS)
	if err != nil || state.LockedOut != nil || state.PasswordExpired != nil {
		t.Fatal(state, err)
	}
	object.Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("8388624")}
	state, err = decodeAccountControl(object, DirectoryADDS)
	if err != nil || !*state.LockedOut || !*state.PasswordExpired {
		t.Fatal(state, err)
	}
}

func TestAccountControlLDSUsesSeparateExactAttributes(t *testing.T) {
	yes, no := true, false
	object := accountTestEntry(0x200)
	delete(object.Attributes, "useraccountcontrol")
	patch := AccountControlPatch{Enabled: &yes, PasswordNotRequired: &no, PasswordNeverExpires: &yes, AllowReversiblePasswordEncryption: &no}
	writes, verification, err := accountControlChanges(object, DirectoryADLDS, patch)
	if err != nil || len(writes) != 4 || len(verification) != 4 {
		t.Fatal(writes, verification, err)
	}
	want := map[string]string{"msDS-UserAccountDisabled": "FALSE", "ms-DS-UserPasswordNotRequired": "FALSE", "msDS-UserDontExpirePassword": "TRUE", "ms-DS-UserEncryptedTextPasswordAllowed": "FALSE"}
	for _, write := range writes {
		if write.operation != 2 || len(write.values) != 1 || want[write.attribute] != string(write.values[0]) {
			t.Fatal(write)
		}
		object.Attributes[strings.ToLower(write.attribute)] = write.values
	}
	writes, _, err = accountControlChanges(object, DirectoryADLDS, patch)
	if err != nil || len(writes) != 0 {
		t.Fatal(writes, err)
	}
	state, err := decodeAccountControl(object, DirectoryADLDS)
	if err != nil || state.StoredFlags != nil || !*state.Enabled || *state.PasswordNotRequired || !*state.PasswordNeverExpires || *state.AllowReversiblePasswordEncryption || state.TrustedForDelegation != nil {
		t.Fatal(state, err)
	}
	if _, _, err := accountControlChanges(object, DirectoryADLDS, AccountControlPatch{SmartcardLogonRequired: &yes}); !errors.Is(err, ErrAccountControlUnsupported) {
		t.Fatal(err)
	}
}

func TestAccountControlPasswordLastSetInstructions(t *testing.T) {
	yes, no := true, false
	object := accountTestEntry(0x200)
	for _, value := range []bool{true, false} {
		writes, verification, err := accountControlChanges(object, DirectoryADDS, AccountControlPatch{ChangePasswordAtLogon: &value})
		if err != nil || len(writes) != 1 || writes[0].attribute != "pwdLastSet" || writes[0].operation != 2 {
			t.Fatal(writes, err)
		}
		if value && (string(writes[0].values[0]) != "0" || len(verification) != 1) {
			t.Fatal(writes, verification)
		}
		if !value && (string(writes[0].values[0]) != "-1" || len(verification) != 0) {
			t.Fatal(writes, verification)
		}
	}
	for _, patch := range []AccountControlPatch{
		{PasswordNeverExpires: &yes, ChangePasswordAtLogon: &yes},
		{ChangePasswordAtLogon: &yes},
	} {
		if _, _, err := accountControlChanges(accountTestEntry(0x10200), DirectoryADDS, patch); !errors.Is(err, ErrInvalidAccountControl) {
			t.Fatal(err)
		}
	}
	if _, _, err := accountControlChanges(accountTestEntry(0x10200), DirectoryADDS, AccountControlPatch{PasswordNeverExpires: &no, ChangePasswordAtLogon: &yes}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountControlNeverExpiresChecksExistingPasswordRequirement(t *testing.T) {
	yes, no := true, false
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, tc := range []struct {
			name    string
			values  [][]byte
			missing bool
			want    error
		}{
			{name: "required", values: [][]byte{[]byte("0")}, want: ErrInvalidAccountControl},
			{name: "hidden-or-missing", missing: true, want: ErrAttributeUnavailable},
			{name: "empty-set", want: ErrInvalidValue},
			{name: "empty-value", values: [][]byte{{}}, want: ErrInvalidValue},
			{name: "malformed", values: [][]byte{[]byte("not-a-timestamp")}, want: ErrInvalidValue},
			{name: "negative-instruction", values: [][]byte{[]byte("-1")}, want: ErrInvalidValue},
			{name: "overflow", values: [][]byte{[]byte("18446744073709551616")}, want: ErrInvalidValue},
			{name: "multiple", values: [][]byte{[]byte("0"), []byte("123456")}, want: ErrInvalidValue},
			{name: "positive", values: [][]byte{[]byte("123456")}},
		} {
			for _, override := range []bool{false, true} {
				name := kind + "/" + tc.name
				if override {
					name += "/explicit-clear"
				}
				t.Run(name, func(t *testing.T) {
					reads, writes := 0, 0
					client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
						reads++
						if !slices.Contains(query.Properties, "pwdLastSet") {
							t.Fatal("missing required projection", query.Properties)
						}
						flags := Flags32(0x40000200)
						if writes != 0 {
							flags |= 0x10000
						}
						object := accountTestEntry(flags)
						if kind == CapabilityADLDS {
							delete(object.Attributes, "useraccountcontrol")
							text := "FALSE"
							if writes != 0 {
								text = "TRUE"
							}
							object.Attributes["msds-userdontexpirepassword"] = [][]byte{[]byte(text)}
						}
						if writes == 0 {
							if tc.missing {
								delete(object.Attributes, "pwdlastset")
							} else {
								object.Attributes["pwdlastset"] = tc.values
							}
						}
						return objectTestCursor(object), nil
					}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
						writes++
						var want []ldapAttributeModification
						if kind == CapabilityADLDS {
							want = []ldapAttributeModification{{operation: 2, attribute: "msDS-UserDontExpirePassword", values: [][]byte{[]byte("TRUE")}}}
						} else {
							// Retain the unrelated 0x40000000 bit and account type.
							want = []ldapAttributeModification{{operation: 1, attribute: "userAccountControl", values: [][]byte{[]byte("1073742336")}}, {operation: 0, attribute: "userAccountControl", values: [][]byte{[]byte("1073807872")}}}
						}
						if override {
							want = append(want, ldapAttributeModification{operation: 2, attribute: "pwdLastSet", values: [][]byte{[]byte("-1")}})
						}
						if request.operation != ldapWriteModify || !reflect.DeepEqual(request.modifications, want) || len(request.controls) != 0 {
							t.Fatal(request)
						}
						return ldapWriteAttempt{State: ldapWriteAccepted}
					})
					session := client.session.(objectWriteTestSession)
					session.read = func(context.Context, []string) (map[string][][]byte, error) { return identityTestRoot(kind), nil }
					client.session = session
					patch := AccountControlPatch{PasswordNeverExpires: &yes}
					if override {
						patch.ChangePasswordAtLogon = &no
					}
					result, err := client.UpdateAccountControl(context.Background(), AccountControlRequest{Identity: objectTestIdentity(), Patch: patch})
					if tc.want != nil && !override {
						if !errors.Is(err, tc.want) || writes != 0 || reads != 1 || result.Mutation.State != ObjectWriteNotAttempted || result.Mutation.Verified || result.Mutation.Before == nil {
							t.Fatal(result, err, reads, writes)
						}
					} else if err != nil || writes != 1 || reads != 2 || result.Mutation.State != ObjectWriteAccepted || !result.Mutation.Verified || result.Account == nil || result.Account.PasswordNeverExpires == nil || !*result.Account.PasswordNeverExpires {
						t.Fatal(result, err, reads, writes)
					}
				})
			}
		}
	}
}

func TestAccountControlOtherFlagsDoNotRequirePasswordTimestamp(t *testing.T) {
	no := false
	for _, kind := range []DirectoryType{DirectoryADDS, DirectoryADLDS} {
		object := accountTestEntry(0x200)
		delete(object.Attributes, "pwdlastset")
		if kind == DirectoryADLDS {
			delete(object.Attributes, "useraccountcontrol")
		}
		for _, patch := range []AccountControlPatch{{Enabled: &no}, {PasswordNeverExpires: &no}} {
			if _, _, err := accountControlChanges(object, kind, patch); err != nil {
				t.Fatal(kind, patch, err)
			}
		}
	}
}

func TestAccountControlOutcomesAndNoReplay(t *testing.T) {
	for _, mode := range []string{"accepted", "rejected", "uncertain", "readback", "wrong-class", "missing-uac", "noop"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			denied := &LDAPError{Code: 50, Diagnostic: "private"}
			client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
				reads++
				if !slices.Contains(query.Properties, "extensionAttribute1") {
					t.Fatal("lost extra property", query.Properties)
				}
				flags := Flags32(0x40000200)
				if writes > 0 || mode == "noop" {
					flags |= 2
				}
				object := accountTestEntry(flags)
				object.Attributes["extensionattribute1"] = [][]byte{[]byte("retained")}
				if mode == "wrong-class" {
					object.Attributes["objectclass"] = [][]byte{[]byte("group")}
				}
				if mode == "missing-uac" {
					delete(object.Attributes, "useraccountcontrol")
				}
				if reads > 1 && mode == "readback" {
					return nil, denied
				}
				return objectTestCursor(object), nil
			}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				if request.operation != ldapWriteModify || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.modifications) != 2 || request.modifications[0].operation != 1 || request.modifications[1].operation != 0 {
					t.Fatal(request)
				}
				if mode == "rejected" {
					return ldapWriteAttempt{State: ldapWriteRejected, Err: denied}
				}
				if mode == "uncertain" {
					return ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
				}
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			result, err := client.DisableAccount(context.Background(), objectTestIdentity(), ObjectMutationOptions{Properties: []string{"extensionAttribute1"}})
			switch mode {
			case "accepted":
				if err != nil || !result.Mutation.Verified || result.Account == nil || *result.Account.Enabled || writes != 1 || reads != 2 {
					t.Fatal(result, err, reads, writes)
				}
			case "rejected":
				if !errors.Is(err, denied) || !errors.Is(err, ErrObjectWritePermission) || result.Mutation.State != ObjectWriteRejected || writes != 1 || reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			case "uncertain":
				if !errors.Is(err, ErrObjectWriteUncertain) || result.Mutation.State != ObjectWriteUncertain || writes != 1 || reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			case "readback":
				if !errors.Is(err, ErrObjectReadback) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || writes != 1 {
					t.Fatal(result, err, writes)
				}
			case "wrong-class":
				if !errors.Is(err, ErrAccountControlTarget) || writes != 0 {
					t.Fatal(result, err, writes)
				}
			case "missing-uac":
				if !errors.Is(err, ErrAttributeUnavailable) || writes != 0 {
					t.Fatal(result, err, writes)
				}
			case "noop":
				if err != nil || !result.Mutation.Verified || result.Mutation.State != ObjectWriteNotAttempted || writes != 0 || reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			}
		})
	}
}

func TestUnlockAccountOnlyWritesLockoutTime(t *testing.T) {
	for _, locked := range []bool{false, true} {
		writes := 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			object := accountTestEntry(0x202)
			if writes == 0 && locked {
				object.Attributes["lockouttime"] = [][]byte{[]byte("1234")}
				object.Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("16")}
			}
			return objectTestCursor(object), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			want := []ldapAttributeModification{{operation: 2, attribute: "lockoutTime", values: [][]byte{[]byte("0")}}}
			if !reflect.DeepEqual(request.modifications, want) {
				t.Fatal(request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		result, err := client.UnlockAccount(context.Background(), objectTestIdentity(), ObjectMutationOptions{})
		if err != nil || writes != 1 || !result.Mutation.Verified || *result.Account.Enabled || *result.Account.LockedOut {
			t.Fatal(result, err, writes)
		}
	}
}

func TestAccountControlNoopCannotAssertVersion(t *testing.T) {
	client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
		return objectTestCursor(accountTestEntry(0x202)), nil
	}, func(context.Context, ldapWriteRequest) ldapWriteAttempt { t.Fatal("write"); return ldapWriteAttempt{} })
	result, err := client.DisableAccount(context.Background(), objectTestIdentity(), ObjectMutationOptions{ExpectedVersion: &ObjectVersion{GUID: objectTestGUID()}})
	if !errors.Is(err, ErrObjectControlUnsupported) || result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestAccountControlPasswordTimestampReadback(t *testing.T) {
	no := false
	for _, readback := range []string{"0", "-1", "123456"} {
		writes := 0
		client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
			object := accountTestEntry(0x200)
			if writes > 0 {
				object.Attributes["pwdlastset"] = [][]byte{[]byte(readback)}
			}
			return objectTestCursor(object), nil
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if len(request.modifications) != 1 || string(request.modifications[0].values[0]) != "-1" {
				t.Fatal(request)
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		result, err := client.UpdateAccountControl(context.Background(), AccountControlRequest{Identity: objectTestIdentity(), Patch: AccountControlPatch{ChangePasswordAtLogon: &no}})
		if (err == nil) != (readback == "123456") || result.Mutation.Verified != (readback == "123456") || result.Mutation.State != ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
}
