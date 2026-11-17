package acceptance

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func InternalAccountTestEntry(flags admodel.Flags32) admodel.Object {
	object := InternalObjectTestEntry("CN=sample,DC=example")
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
			InternalPatch   admodel.AccountControlPatch
			InternalMask    admodel.Flags32
			InternalInverse bool
		}{
			{admodel.AccountControlPatch{Enabled: &enabled}, 2, true},
			{admodel.AccountControlPatch{HomeDirectoryRequired: &enabled}, 8, false},
			{admodel.AccountControlPatch{PasswordNotRequired: &enabled}, 32, false},
			{admodel.AccountControlPatch{AllowReversiblePasswordEncryption: &enabled}, 128, false},
			{admodel.AccountControlPatch{PasswordNeverExpires: &enabled}, 65536, false},
			{admodel.AccountControlPatch{MNSLogonAccount: &enabled}, 131072, false},
			{admodel.AccountControlPatch{SmartcardLogonRequired: &enabled}, 262144, false},
			{admodel.AccountControlPatch{TrustedForDelegation: &enabled}, 524288, false},
			{admodel.AccountControlPatch{AccountNotDelegated: &enabled}, 1048576, false},
			{admodel.AccountControlPatch{UseDESKeyOnly: &enabled}, 2097152, false},
			{admodel.AccountControlPatch{DoesNotRequirePreAuth: &enabled}, 4194304, false},
			{admodel.AccountControlPatch{TrustedToAuthForDelegation: &enabled}, 16777216, false},
		}
		for _, tc := range fields {
			old := admodel.Flags32(0x40000200).With(tc.InternalMask, enabled == tc.InternalInverse)
			writes, verify, err := admodel.InternalAccountControlChanges(
				InternalAccountTestEntry(old),
				admodel.DirectoryADDS,
				tc.InternalPatch,
			)
			if err != nil || len(writes) != 2 || len(verify) != 1 {
				t.Fatal(tc, err, writes, verify)
			}
			next, err := admodel.NewRawValue(writes[1].InternalValues[0]).Flags32()
			if err != nil || next&^tc.InternalMask != old&^tc.InternalMask ||
				next.Has(tc.InternalMask) != (enabled != tc.InternalInverse) ||
				writes[0].InternalOperation != 1 ||
				writes[1].InternalOperation != 0 ||
				string(writes[0].InternalValues[0]) != old.LDAPString() {
				t.Fatal(tc, writes, next, err)
			}
		}
	}
}

func TestAccountControlComputedStateIsNotStoredFlagsOrTimestamp(t *testing.T) {
	object := InternalAccountTestEntry(0x800010 | 0x200)
	object.Attributes["lockouttime"] = [][]byte{[]byte("100")}
	state, err := admodel.InternalDecodeAccountControl(object, admodel.DirectoryADDS)
	if err != nil || state.LockedOut == nil || *state.LockedOut || *state.PasswordExpired ||
		*state.LockoutTime != 100 {
		t.Fatal(state, err)
	}
	delete(object.Attributes, "msds-user-account-control-computed")
	state, err = admodel.InternalDecodeAccountControl(object, admodel.DirectoryADDS)
	if err != nil || state.LockedOut != nil || state.PasswordExpired != nil {
		t.Fatal(state, err)
	}
	object.Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("8388624")}
	state, err = admodel.InternalDecodeAccountControl(object, admodel.DirectoryADDS)
	if err != nil || !*state.LockedOut || !*state.PasswordExpired {
		t.Fatal(state, err)
	}
}

func TestAccountControlLDSUsesSeparateExactAttributes(t *testing.T) {
	yes, no := true, false
	object := InternalAccountTestEntry(0x200)
	delete(object.Attributes, "useraccountcontrol")
	patch := admodel.AccountControlPatch{
		Enabled:                           &yes,
		PasswordNotRequired:               &no,
		PasswordNeverExpires:              &yes,
		AllowReversiblePasswordEncryption: &no,
	}
	writes, verification, err := admodel.InternalAccountControlChanges(
		object,
		admodel.DirectoryADLDS,
		patch,
	)
	if err != nil || len(writes) != 4 || len(verification) != 4 {
		t.Fatal(writes, verification, err)
	}
	want := map[string]string{
		"msDS-UserAccountDisabled":               "FALSE",
		"ms-DS-UserPasswordNotRequired":          "FALSE",
		"msDS-UserDontExpirePassword":            "TRUE",
		"ms-DS-UserEncryptedTextPasswordAllowed": "FALSE",
	}
	for _, write := range writes {
		if write.InternalOperation != 2 || len(write.InternalValues) != 1 ||
			want[write.InternalAttribute] != string(write.InternalValues[0]) {
			t.Fatal(write)
		}
		object.Attributes[strings.ToLower(write.InternalAttribute)] = write.InternalValues
	}
	writes, _, err = admodel.InternalAccountControlChanges(object, admodel.DirectoryADLDS, patch)
	if err != nil || len(writes) != 0 {
		t.Fatal(writes, err)
	}
	state, err := admodel.InternalDecodeAccountControl(object, admodel.DirectoryADLDS)
	if err != nil || state.StoredFlags != nil || !*state.Enabled || *state.PasswordNotRequired ||
		!*state.PasswordNeverExpires ||
		*state.AllowReversiblePasswordEncryption ||
		state.TrustedForDelegation != nil {
		t.Fatal(state, err)
	}
	if _, _, err := admodel.InternalAccountControlChanges(
		object,
		admodel.DirectoryADLDS,
		admodel.AccountControlPatch{SmartcardLogonRequired: &yes},
	); !errors.Is(
		err,
		admodel.ErrAccountControlUnsupported,
	) {
		t.Fatal(err)
	}
}

func TestAccountControlPasswordLastSetInstructions(t *testing.T) {
	yes, no := true, false
	object := InternalAccountTestEntry(0x200)
	for _, value := range []bool{true, false} {
		writes, verification, err := admodel.InternalAccountControlChanges(
			object,
			admodel.DirectoryADDS,
			admodel.AccountControlPatch{ChangePasswordAtLogon: &value},
		)
		if err != nil || len(writes) != 1 || writes[0].InternalAttribute != "pwdLastSet" ||
			writes[0].InternalOperation != 2 {
			t.Fatal(writes, err)
		}
		if value && (string(writes[0].InternalValues[0]) != "0" || len(verification) != 1) {
			t.Fatal(writes, verification)
		}
		if !value && (string(writes[0].InternalValues[0]) != "-1" || len(verification) != 0) {
			t.Fatal(writes, verification)
		}
	}
	for _, patch := range []admodel.AccountControlPatch{
		{PasswordNeverExpires: &yes, ChangePasswordAtLogon: &yes},
		{ChangePasswordAtLogon: &yes},
	} {
		if _, _, err := admodel.InternalAccountControlChanges(
			InternalAccountTestEntry(0x10200),
			admodel.DirectoryADDS,
			patch,
		); !errors.Is(
			err,
			admodel.ErrInvalidAccountControl,
		) {
			t.Fatal(err)
		}
	}
	if _, _, err := admodel.InternalAccountControlChanges(
		InternalAccountTestEntry(0x10200),
		admodel.DirectoryADDS,
		admodel.AccountControlPatch{PasswordNeverExpires: &no, ChangePasswordAtLogon: &yes},
	); err != nil {
		t.Fatal(err)
	}
}

func TestAccountControlNeverExpiresChecksExistingPasswordRequirement(t *testing.T) {
	yes, no := true, false
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, tc := range []struct {
			InternalName    string
			InternalValues  [][]byte
			InternalMissing bool
			InternalWant    error
		}{
			{InternalName: "required", InternalValues: [][]byte{[]byte("0")}, InternalWant: admodel.ErrInvalidAccountControl},
			{InternalName: "hidden-or-missing", InternalMissing: true, InternalWant: admodel.ErrAttributeUnavailable},
			{InternalName: "empty-set", InternalWant: admodel.ErrInvalidValue},
			{InternalName: "empty-value", InternalValues: [][]byte{{}}, InternalWant: admodel.ErrInvalidValue},
			{InternalName: "malformed", InternalValues: [][]byte{[]byte("not-a-timestamp")}, InternalWant: admodel.ErrInvalidValue},
			{InternalName: "negative-instruction", InternalValues: [][]byte{[]byte("-1")}, InternalWant: admodel.ErrInvalidValue},
			{InternalName: "overflow", InternalValues: [][]byte{[]byte("18446744073709551616")}, InternalWant: admodel.ErrInvalidValue},
			{InternalName: "multiple", InternalValues: [][]byte{[]byte("0"), []byte("123456")}, InternalWant: admodel.ErrInvalidValue},
			{InternalName: "positive", InternalValues: [][]byte{[]byte("123456")}},
		} {
			for _, override := range []bool{false, true} {
				name := kind + "/" + tc.InternalName
				if override {
					name += "/explicit-clear"
				}
				t.Run(name, func(t *testing.T) {
					reads, writes := 0, 0
					client := InternalObjectTestClient(
						t,
						nil,
						func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
							reads++
							if !slices.Contains(query.Properties, "pwdLastSet") {
								t.Fatal("missing required projection", query.Properties)
							}
							flags := admodel.Flags32(0x40000200)
							if writes != 0 {
								flags |= 0x10000
							}
							object := InternalAccountTestEntry(flags)
							if kind == admodel.CapabilityADLDS {
								delete(object.Attributes, "useraccountcontrol")
								text := "FALSE"
								if writes != 0 {
									text = "TRUE"
								}
								object.Attributes["msds-userdontexpirepassword"] = [][]byte{
									[]byte(text),
								}
							}
							if writes == 0 {
								if tc.InternalMissing {
									delete(object.Attributes, "pwdlastset")
								} else {
									object.Attributes["pwdlastset"] = tc.InternalValues
								}
							}
							return InternalObjectTestCursor(object), nil
						},
						func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
							writes++
							var want []admodel.InternalLdapAttributeModification
							if kind == admodel.CapabilityADLDS {
								want = []admodel.InternalLdapAttributeModification{
									{
										InternalOperation: 2,
										InternalAttribute: "msDS-UserDontExpirePassword",
										InternalValues:    [][]byte{[]byte("TRUE")},
									},
								}
							} else {
								// Retain the unrelated 0x40000000 bit and account type.
								want = []admodel.InternalLdapAttributeModification{
									{
										InternalOperation: 1,
										InternalAttribute: "userAccountControl",
										InternalValues:    [][]byte{[]byte("1073742336")},
									},
									{
										InternalOperation: 0,
										InternalAttribute: "userAccountControl",
										InternalValues:    [][]byte{[]byte("1073807872")},
									},
								}
							}
							if override {
								want = append(
									want,
									admodel.InternalLdapAttributeModification{
										InternalOperation: 2,
										InternalAttribute: "pwdLastSet",
										InternalValues:    [][]byte{[]byte("-1")},
									},
								)
							}
							if request.InternalOperation != admodel.InternalLdapWriteModify ||
								!reflect.DeepEqual(request.InternalModifications, want) ||
								len(request.InternalControls) != 0 {
								t.Fatal(request)
							}
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteAccepted,
							}
						},
					)
					session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
					session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
						return InternalIdentityTestRoot(kind), nil
					}
					(*adengine.InternalClientSessionPointer(client)) = session
					patch := admodel.AccountControlPatch{PasswordNeverExpires: &yes}
					if override {
						patch.ChangePasswordAtLogon = &no
					}
					result, err := adservice_accounts.New(client).
						UpdateAccountControl(context.Background(), admodel.AccountControlRequest{Identity: InternalObjectTestIdentity(), Patch: patch})
					if tc.InternalWant != nil && !override {
						if !errors.Is(err, tc.InternalWant) || writes != 0 || reads != 1 ||
							result.Mutation.State != admodel.ObjectWriteNotAttempted ||
							result.Mutation.Verified ||
							result.Mutation.Before == nil {
							t.Fatal(result, err, reads, writes)
						}
					} else if err != nil || writes != 1 || reads != 2 || result.Mutation.State != admodel.ObjectWriteAccepted || !result.Mutation.Verified || result.Account == nil || result.Account.PasswordNeverExpires == nil || !*result.Account.PasswordNeverExpires {
						t.Fatal(result, err, reads, writes)
					}
				})
			}
		}
	}
}

func TestAccountControlOtherFlagsDoNotRequirePasswordTimestamp(t *testing.T) {
	no := false
	for _, kind := range []admodel.DirectoryType{admodel.DirectoryADDS, admodel.DirectoryADLDS} {
		object := InternalAccountTestEntry(0x200)
		delete(object.Attributes, "pwdlastset")
		if kind == admodel.DirectoryADLDS {
			delete(object.Attributes, "useraccountcontrol")
		}
		for _, patch := range []admodel.AccountControlPatch{{Enabled: &no}, {PasswordNeverExpires: &no}} {
			if _, _, err := admodel.InternalAccountControlChanges(object, kind, patch); err != nil {
				t.Fatal(kind, patch, err)
			}
		}
	}
}

func TestAccountControlOutcomesAndNoReplay(t *testing.T) {
	for _, mode := range []string{"accepted", "rejected", "uncertain", "readback", "wrong-class", "missing-uac", "noop"} {
		t.Run(mode, func(t *testing.T) {
			reads, writes := 0, 0
			denied := &admodel.LDAPError{Code: 50, Diagnostic: "private"}
			client := InternalObjectTestClient(
				t,
				nil,
				func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					reads++
					if !slices.Contains(query.Properties, "extensionAttribute1") {
						t.Fatal("lost extra property", query.Properties)
					}
					flags := admodel.Flags32(0x40000200)
					if writes > 0 || mode == "noop" {
						flags |= 2
					}
					object := InternalAccountTestEntry(flags)
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
					return InternalObjectTestCursor(object), nil
				},
				func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					if request.InternalOperation != admodel.InternalLdapWriteModify ||
						request.InternalDn != admodel.InternalObjectGUIDTarget(
							InternalObjectTestGUID(),
						) ||
						len(request.InternalModifications) != 2 ||
						request.InternalModifications[0].InternalOperation != 1 ||
						request.InternalModifications[1].InternalOperation != 0 {
						t.Fatal(request)
					}
					if mode == "rejected" {
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteRejected,
							Err:   denied,
						}
					}
					if mode == "uncertain" {
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteUncertain,
							Err:   context.DeadlineExceeded,
						}
					}
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			result, err := adservice_accounts.New(client).
				DisableAccount(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{Properties: []string{"extensionAttribute1"}})
			switch mode {
			case "accepted":
				if err != nil || !result.Mutation.Verified || result.Account == nil ||
					*result.Account.Enabled ||
					writes != 1 ||
					reads != 2 {
					t.Fatal(result, err, reads, writes)
				}
			case "rejected":
				if !errors.Is(err, denied) || !errors.Is(err, admodel.ErrObjectWritePermission) ||
					result.Mutation.State != admodel.ObjectWriteRejected ||
					writes != 1 ||
					reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			case "uncertain":
				if !errors.Is(err, admodel.ErrObjectWriteUncertain) ||
					result.Mutation.State != admodel.ObjectWriteUncertain ||
					writes != 1 ||
					reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			case "readback":
				if !errors.Is(err, admodel.ErrObjectReadback) ||
					result.Mutation.State != admodel.ObjectWriteAccepted ||
					result.Mutation.Verified ||
					writes != 1 {
					t.Fatal(result, err, writes)
				}
			case "wrong-class":
				if !errors.Is(err, admodel.ErrAccountControlTarget) || writes != 0 {
					t.Fatal(result, err, writes)
				}
			case "missing-uac":
				if !errors.Is(err, admodel.ErrAttributeUnavailable) || writes != 0 {
					t.Fatal(result, err, writes)
				}
			case "noop":
				if err != nil || !result.Mutation.Verified ||
					result.Mutation.State != admodel.ObjectWriteNotAttempted ||
					writes != 0 ||
					reads != 1 {
					t.Fatal(result, err, reads, writes)
				}
			}
		})
	}
}

func TestUnlockAccountOnlyWritesLockoutTime(t *testing.T) {
	for _, locked := range []bool{false, true} {
		writes := 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				object := InternalAccountTestEntry(0x202)
				if writes == 0 && locked {
					object.Attributes["lockouttime"] = [][]byte{[]byte("1234")}
					object.Attributes["msds-user-account-control-computed"] = [][]byte{[]byte("16")}
				}
				return InternalObjectTestCursor(object), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				want := []admodel.InternalLdapAttributeModification{
					{
						InternalOperation: 2,
						InternalAttribute: "lockoutTime",
						InternalValues:    [][]byte{[]byte("0")},
					},
				}
				if !reflect.DeepEqual(request.InternalModifications, want) {
					t.Fatal(request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		result, err := adservice_accounts.New(client).
			UnlockAccount(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{})
		if err != nil || writes != 1 || !result.Mutation.Verified || *result.Account.Enabled ||
			*result.Account.LockedOut {
			t.Fatal(result, err, writes)
		}
	}
}

func TestAccountControlNoopCannotAssertVersion(t *testing.T) {
	client := InternalObjectTestClient(
		t,
		nil,
		func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
			return InternalObjectTestCursor(InternalAccountTestEntry(0x202)), nil
		},
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			t.Fatal("write")
			return admodel.InternalLdapWriteAttempt{}
		},
	)
	result, err := adservice_accounts.New(client).
		DisableAccount(context.Background(), InternalObjectTestIdentity(), admodel.ObjectMutationOptions{ExpectedVersion: &admodel.ObjectVersion{GUID: InternalObjectTestGUID()}})
	if !errors.Is(err, admodel.ErrObjectControlUnsupported) || result.Mutation.Verified {
		t.Fatal(result, err)
	}
}

func TestAccountControlPasswordTimestampReadback(t *testing.T) {
	no := false
	for _, readback := range []string{"0", "-1", "123456"} {
		writes := 0
		client := InternalObjectTestClient(
			t,
			nil,
			func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				object := InternalAccountTestEntry(0x200)
				if writes > 0 {
					object.Attributes["pwdlastset"] = [][]byte{[]byte(readback)}
				}
				return InternalObjectTestCursor(object), nil
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if len(request.InternalModifications) != 1 ||
					string(request.InternalModifications[0].InternalValues[0]) != "-1" {
					t.Fatal(request)
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		result, err := adservice_accounts.New(client).
			UpdateAccountControl(context.Background(), admodel.AccountControlRequest{Identity: InternalObjectTestIdentity(), Patch: admodel.AccountControlPatch{ChangePasswordAtLogon: &no}})
		if (err == nil) != (readback == "123456") ||
			result.Mutation.Verified != (readback == "123456") ||
			result.Mutation.State != admodel.ObjectWriteAccepted {
			t.Fatal(result, err)
		}
	}
}
