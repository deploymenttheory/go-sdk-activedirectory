package acceptance

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

type InternalPasswordTestSession struct {
	InternalObjectWriteTestSession
	InternalProtect func(context.Context, admodel.Transport) (admodel.PasswordProtection, error)
}

func (s InternalPasswordTestSession) InternalPasswordProtection(
	ctx context.Context,
	transport admodel.Transport,
) (admodel.PasswordProtection, error) {
	return s.InternalProtect(ctx, transport)
}

func InternalPasswordTestClient(
	t *testing.T,
	kind string,
	protect func(context.Context, admodel.Transport) (admodel.PasswordProtection, error),
	search func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error),
	write func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt,
) *adengine.Client {
	t.Helper()
	client := adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc.example", Port: 389},
			Timeout:  time.Second,
		},
		InternalPasswordTestSession{
			InternalObjectWriteTestSession: InternalObjectWriteTestSession{
				InternalTestSession: InternalTestSession{
					InternalBase: func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
						if base != "" {
							return map[string][][]byte{"msds-isrodc": {[]byte("FALSE")}}, nil
						}
						root := InternalIdentityTestRoot(kind)
						root["dsservicename"] = [][]byte{
							[]byte("CN=NTDS Settings,CN=DC,CN=Configuration,DC=example"),
						}
						return root, nil
					},
					InternalSearch: search,
					InternalFinish: func() error { return nil },
				},
				InternalWrite: write,
			},
			InternalProtect: protect,
		},
	)
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}

func InternalPasswordTestProtection(
	_ context.Context,
	transport admodel.Transport,
) (admodel.PasswordProtection, error) {
	return admodel.PasswordProtection{Transport: transport, CipherBits: 128}, nil
}

func InternalPasswordTestSearch(
	_ context.Context,
	query admodel.SearchOptions,
) (admodel.InternalSearchCursor, error) {
	entry := InternalObjectTestEntry("CN=sample,DC=example")
	entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("user")}
	return InternalObjectTestCursor(entry), nil
}

func TestPasswordEncodingUnicodeQuotesAndEmpty(t *testing.T) {
	for _, tc := range []struct{ InternalValue, InternalWant string }{{"new", "22006e00650077002200"}, {"李😀\"", "22004e673dd800de22002200"}, {"", "22002200"}} {
		want, _ := hex.DecodeString(tc.InternalWant)
		if got := admodel.InternalQuotedPasswordUTF16(
			[]byte(tc.InternalValue),
		); !bytes.Equal(
			got,
			want,
		) {
			t.Fatal("quoted UTF-16LE differs from public fixture")
		}
	}
	for _, value := range [][]byte{nil, {0}, {0xff}, {0xed, 0xa0, 0x80}} {
		if !errors.Is(
			admodel.InternalValidatePasswordBytes(value),
			admodel.ErrInvalidPasswordRequest,
		) {
			t.Fatal("accepted omitted/invalid password")
		}
	}
	if err := admodel.InternalValidatePasswordBytes([]byte{}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordRequestsRedactFormattingAndSerialization(t *testing.T) {
	for _, request := range []any{admodel.PasswordChangeRequest{OldPassword: []byte("PUBLIC-OLD"), NewPassword: []byte("PUBLIC-NEW")}, admodel.PasswordResetRequest{NewPassword: []byte("PUBLIC-NEW")}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if bytes.Contains([]byte(fmt.Sprintf(format, request)), []byte("PUBLIC")) {
				t.Fatal("formatting exposed password fixture")
			}
		}
		encoded, err := json.Marshal(request)
		if err != nil || string(encoded) != `{"redacted":true}` {
			t.Fatal("JSON did not redact request")
		}
	}
}

func TestPasswordChangeResetSingleWriteAndBufferLifetime(t *testing.T) {
	for _, change := range []bool{true, false} {
		oldPassword, newPassword := []byte("PUBLIC-old-李"), []byte("PUBLIC-new-😀")
		reads, writes, protections := 0, 0, 0
		var nativeBuffers [][]byte
		client := InternalPasswordTestClient(
			t,
			admodel.CapabilityActiveDirectory,
			func(ctx context.Context, transport admodel.Transport) (admodel.PasswordProtection, error) {
				protections++
				return InternalPasswordTestProtection(ctx, transport)
			},
			func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				reads++
				for _, name := range query.Properties {
					if name == "unicodePwd" {
						t.Fatal("password readback requested")
					}
				}
				return InternalPasswordTestSearch(ctx, query)
			},
			func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				if request.InternalOperation != admodel.InternalLdapWriteModify ||
					request.InternalDn != "<GUID=33221100554477668899aabbccddeeff>" ||
					len(request.InternalControls) != 0 {
					t.Fatal("wrong password write target")
				}
				if change {
					if len(request.InternalModifications) != 2 ||
						request.InternalModifications[0].InternalOperation != 1 ||
						request.InternalModifications[1].InternalOperation != 0 ||
						!bytes.Equal(
							request.InternalModifications[0].InternalValues[0],
							admodel.InternalQuotedPasswordUTF16(oldPassword),
						) {
						t.Fatal("password change operations differ")
					}
				} else if len(request.InternalModifications) != 1 || request.InternalModifications[0].InternalOperation != 2 {
					t.Fatal("password reset must be one replace")
				}
				for _, mod := range request.InternalModifications {
					if mod.InternalAttribute != "unicodePwd" || len(mod.InternalValues) != 1 {
						t.Fatal("unexpected password attribute")
					}
					nativeBuffers = append(nativeBuffers, mod.InternalValues[0])
				}
				if !bytes.Equal(
					nativeBuffers[len(nativeBuffers)-1],
					admodel.InternalQuotedPasswordUTF16(newPassword),
				) {
					t.Fatal("new password encoding differs")
				}
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		var result admodel.PasswordResult
		var err error
		if change {
			result, err = adservice_accounts.New(client).
				ChangeAccountPassword(context.Background(), admodel.PasswordChangeRequest{Identity: InternalObjectTestIdentity(), OldPassword: oldPassword, NewPassword: newPassword})
		} else {
			result, err = adservice_accounts.New(client).
				ResetAccountPassword(context.Background(), admodel.PasswordResetRequest{Identity: InternalObjectTestIdentity(), NewPassword: newPassword})
		}
		if err != nil || result.State != admodel.ObjectWriteAccepted || result.TargetGUID == nil ||
			writes != 1 ||
			reads != 1 ||
			protections != 2 {
			t.Fatalf(
				"state=%d reads=%d writes=%d checks=%d err=%v",
				result.State,
				reads,
				writes,
				protections,
				err,
			)
		}
		for _, buffer := range nativeBuffers {
			if !bytes.Equal(buffer, make([]byte, len(buffer))) {
				t.Fatal("temporary encoded buffer retained plaintext")
			}
		}
		if string(oldPassword) != "PUBLIC-old-李" || string(newPassword) != "PUBLIC-new-😀" {
			t.Fatal("caller password unexpectedly modified")
		}
	}
}

func TestPasswordOutcomesPreserveDiagnosticsAndNeverReplay(t *testing.T) {
	for _, tc := range []struct {
		InternalName    string
		InternalAttempt admodel.InternalLdapWriteAttempt
		InternalWant    error
		InternalState   admodel.ObjectWriteState
	}{
		{"wrong old", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 49, Diagnostic: "00000056: public synthetic detail"}}, admodel.ErrPasswordCredential, admodel.ObjectWriteRejected},
		{"policy", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 19, Diagnostic: "0000052D: public synthetic detail"}}, admodel.ErrPasswordConstraint, admodel.ObjectWriteRejected},
		{"access", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 50}}, admodel.ErrPasswordAccess, admodel.ObjectWriteRejected},
		{"unwilling ambiguous", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 53}}, nil, admodel.ObjectWriteRejected},
		{"uncertain", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteUncertain, Err: admodel.InternalLDAPWriteUncertainError()}, admodel.ErrPasswordUncertain, admodel.ObjectWriteUncertain},
		{"accepted cleanup", admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted, Err: context.Canceled}, context.Canceled, admodel.ObjectWriteAccepted},
	} {
		t.Run(tc.InternalName, func(t *testing.T) {
			writes := 0
			var buffer []byte
			client := InternalPasswordTestClient(
				t,
				admodel.CapabilityActiveDirectory,
				InternalPasswordTestProtection,
				InternalPasswordTestSearch,
				func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					buffer = request.InternalModifications[0].InternalValues[0]
					return tc.InternalAttempt
				},
			)
			result, err := adservice_accounts.New(client).
				ResetAccountPassword(context.Background(), admodel.PasswordResetRequest{Identity: InternalObjectTestIdentity(), NewPassword: []byte("PUBLIC-test")})
			if err == nil || (tc.InternalWant != nil && !errors.Is(err, tc.InternalWant)) ||
				result.State != tc.InternalState ||
				writes != 1 ||
				!bytes.Equal(buffer, make([]byte, len(buffer))) {
				t.Fatalf("state=%d writes=%d err=%v", result.State, writes, err)
			}
			var native *admodel.LDAPError
			if errors.As(tc.InternalAttempt.Err, &native) {
				var returned *admodel.LDAPError
				if !errors.As(err, &returned) || returned != native {
					t.Fatal("native error lost")
				}
			}
		})
	}
}

func TestPasswordProtectionAndIdentityFailBeforeWrite(t *testing.T) {
	for _, mode := range []string{"insecure", "weak", "downgraded", "canceled", "wrong class", "scope", "LDS SID", "LDS account name", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			checks, writes := 0, 0
			kind := admodel.CapabilityActiveDirectory
			if mode == "LDS SID" || mode == "LDS account name" {
				kind = admodel.CapabilityADLDS
			}
			if mode == "unknown" {
				kind = "unknown"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := InternalPasswordTestClient(
				t,
				kind,
				func(ctx context.Context, transport admodel.Transport) (admodel.PasswordProtection, error) {
					checks++
					if mode == "insecure" || (mode == "downgraded" && checks == 2) {
						return admodel.PasswordProtection{}, admodel.ErrPasswordProtection
					}
					if mode == "weak" {
						return admodel.PasswordProtection{Transport: transport, CipherBits: 56}, nil
					}
					return InternalPasswordTestProtection(ctx, transport)
				},
				func(ctx context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
					if mode == "wrong class" {
						entry := InternalObjectTestEntry("CN=sample,DC=example")
						entry.Attributes["objectclass"] = [][]byte{[]byte("container")}
						return InternalObjectTestCursor(entry), nil
					}
					return InternalPasswordTestSearch(ctx, query)
				},
				func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					return admodel.InternalLdapWriteAttempt{
						State: admodel.InternalLdapWriteAccepted,
					}
				},
			)
			account := InternalObjectTestIdentity()
			if mode == "scope" {
				account, _ = admodel.IdentityByDN("CN=sample,DC=other")
			}
			if mode == "LDS SID" {
				account, _ = admodel.IdentityBySID("S-1-5-21-42")
			}
			if mode == "LDS account name" {
				account, _ = admodel.IdentityByAccountName("sample")
			}
			if mode == "canceled" {
				cancel()
			}
			result, err := adservice_accounts.New(client).
				ResetAccountPassword(ctx, admodel.PasswordResetRequest{Identity: account, NewPassword: []byte("PUBLIC-test")})
			if err == nil || writes != 0 || result.State != admodel.ObjectWriteNotAttempted {
				t.Fatalf("state=%d writes=%d err=%v", result.State, writes, err)
			}
		})
	}
	// LDS user objects need not expose objectSid and may use arbitrary ports.
	client := InternalPasswordTestClient(
		t,
		admodel.CapabilityADLDS,
		InternalPasswordTestProtection,
		InternalPasswordTestSearch,
		func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
		},
	)
	(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
	if result, err := adservice_accounts.New(client).
		ResetAccountPassword(context.Background(), admodel.PasswordResetRequest{Identity: InternalObjectTestIdentity(), NewPassword: []byte("PUBLIC-test")}); err != nil ||
		result.State != admodel.ObjectWriteAccepted {
		t.Fatal(result.State, err)
	}
}

func TestPasswordRODCAndMissingWritableEvidenceReject(t *testing.T) {
	for _, mode := range []string{"RODC", "hidden", "malformed", "GC"} {
		writes := 0
		client := InternalPasswordTestClient(
			t,
			admodel.CapabilityActiveDirectory,
			InternalPasswordTestProtection,
			InternalPasswordTestSearch,
			func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
				writes++
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			},
		)
		session := adengine.InternalClientSession(client).(InternalPasswordTestSession)
		base := session.InternalBase
		session.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
			if dn == "" {
				return base(ctx, dn, properties)
			}
			if mode == "hidden" {
				return map[string][][]byte{}, nil
			}
			value := "TRUE"
			if mode == "malformed" {
				value = "not-a-boolean"
			}
			return map[string][][]byte{"msds-isrodc": {[]byte(value)}}, nil
		}
		(*adengine.InternalClientSessionPointer(client)) = session
		if mode == "GC" {
			(*adengine.InternalClientConfigPointer(client)).Endpoint.Port = 3268
		}
		result, err := adservice_accounts.New(client).
			ResetAccountPassword(context.Background(), admodel.PasswordResetRequest{Identity: InternalObjectTestIdentity(), NewPassword: []byte("PUBLIC-test")})
		if err == nil || writes != 0 || result.State != admodel.ObjectWriteNotAttempted {
			t.Fatal(mode, result.State, err)
		}
	}
}
