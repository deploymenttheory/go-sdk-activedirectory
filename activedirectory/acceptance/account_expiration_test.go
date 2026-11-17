package acceptance

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func InternalAccountStateTime(t *testing.T, text string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestAccountExpirationSentinelsAndPrecision(t *testing.T) {
	for _, raw := range []string{"0", "9223372036854775807", "133802606451234567", "-1", "not-a-time"} {
		object := InternalAccountTestEntry(512)
		object.Attributes["accountexpires"] = [][]byte{[]byte(raw)}
		result, err := admodel.InternalDecodeAccountExpiration(object)
		switch raw {
		case "0", "9223372036854775807":
			if err != nil || result.Value == nil || result.NeverExpires == nil ||
				!*result.NeverExpires ||
				result.ExpiresAt != nil {
				t.Fatal(result, err)
			}
		case "133802606451234567":
			if err != nil || result.NeverExpires == nil || *result.NeverExpires ||
				result.ExpiresAt == nil ||
				result.ExpiresAt.Nanosecond() != 123456700 {
				t.Fatal(result, err)
			}
		default:
			if err == nil || result.NeverExpires != nil {
				t.Fatal(result, err)
			}
		}
	}
	result, err := admodel.InternalDecodeAccountExpiration(InternalAccountTestEntry(512))
	if err != nil || result.Value != nil || result.NeverExpires != nil {
		t.Fatal(result, err)
	}
	utc := InternalAccountStateTime(t, "2026-11-13T11:22:33.1234567Z")
	local := InternalAccountStateTime(t, "2026-11-13T12:22:33.1234567+01:00")
	a, err := admodel.InternalFiniteAccountTime(utc)
	b, other := admodel.InternalFiniteAccountTime(local)
	if err != nil || other != nil || a != b {
		t.Fatal(a, b, err, other)
	}
	for _, bad := range []time.Time{{}, time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), utc.Add(time.Nanosecond), time.Date(1600, 12, 31, 23, 59, 59, 0, time.UTC)} {
		if _, err := admodel.InternalFiniteAccountTime(
			bad,
		); !errors.Is(
			err,
			admodel.ErrInvalidAccountExpiration,
		) {
			t.Fatal(bad, err)
		}
	}
}

func TestAccountExpirationReadClassAndVisibility(t *testing.T) {
	for _, kind := range []string{admodel.CapabilityActiveDirectory, admodel.CapabilityADLDS} {
		for _, mode := range []string{"never", "hidden", "wrong-class"} {
			t.Run(kind+mode, func(t *testing.T) {
				client := InternalObjectTestClient(
					t,
					nil,
					func(_ context.Context, query admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						if !slices.Contains(query.Properties, "accountExpires") {
							t.Fatal(query)
						}
						object := InternalAccountTestEntry(512)
						if mode == "never" {
							object.Attributes["accountexpires"] = [][]byte{[]byte("0")}
						}
						if mode == "wrong-class" {
							object.Attributes["objectclass"] = [][]byte{[]byte("group")}
						}
						return InternalObjectTestCursor(object), nil
					},
					func(context.Context, admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						t.Fatal("read wrote")
						return admodel.InternalLdapWriteAttempt{}
					},
				)
				session := adengine.InternalClientSession(client).(InternalObjectWriteTestSession)
				session.InternalRead = func(context.Context, []string) (map[string][][]byte, error) {
					return InternalIdentityTestRoot(kind), nil
				}
				(*adengine.InternalClientSessionPointer(client)) = session
				result, err := adservice_accounts.New(client).
					AccountExpiration(context.Background(), InternalObjectTestIdentity(), admodel.ResolveIdentityOptions{})
				if mode == "wrong-class" {
					if !errors.Is(err, admodel.ErrAccountControlTarget) ||
						result.Expiration != nil {
						t.Fatal(result, err)
					}
					return
				}
				if err != nil || result.Expiration == nil || !result.Observation.Complete {
					t.Fatal(result, err)
				}
				if mode == "hidden" && result.Expiration.NeverExpires != nil {
					t.Fatal("omission claimed never expire")
				}
			})
		}
	}
}

func TestAccountExpirationMutationOutcomesAndSentinel(t *testing.T) {
	for _, clear := range []bool{false, true} {
		for _, mode := range []string{"accepted", "rejected", "uncertain", "readback-hidden", "changed-readback", "unsupported-assertion", "wrong-class"} {
			t.Run(mode+map[bool]string{false: "/set", true: "/clear"}[clear], func(t *testing.T) {
				at := InternalAccountStateTime(t, "2026-11-13T11:22:33.1234567Z")
				stamp, _ := admodel.InternalFiniteAccountTime(at)
				if clear {
					stamp = math.MaxInt64
				}
				reads, writes := 0, 0
				client := InternalObjectTestClient(
					t,
					nil,
					func(context.Context, admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
						reads++
						object := InternalAccountTestEntry(512)
						object.Attributes["accountexpires"] = [][]byte{[]byte(stamp.LDAPString())}
						if writes != 0 && mode == "readback-hidden" {
							delete(object.Attributes, "accountexpires")
						}
						if writes != 0 && mode == "changed-readback" {
							object.Attributes["accountexpires"] = [][]byte{[]byte("42")}
						}
						if mode == "wrong-class" {
							object.Attributes["objectclass"] = [][]byte{[]byte("group")}
						}
						return InternalObjectTestCursor(object), nil
					},
					func(_ context.Context, request admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
						writes++
						if request.InternalOperation != admodel.InternalLdapWriteModify ||
							request.InternalDn != admodel.InternalObjectGUIDTarget(
								InternalObjectTestGUID(),
							) ||
							len(request.InternalModifications) != 1 ||
							request.InternalModifications[0].InternalOperation != 2 ||
							request.InternalModifications[0].InternalAttribute != "accountExpires" ||
							string(
								request.InternalModifications[0].InternalValues[0],
							) != stamp.LDAPString() {
							t.Fatal(request)
						}
						if mode == "rejected" {
							return admodel.InternalLdapWriteAttempt{
								State: admodel.InternalLdapWriteRejected,
								Err:   &admodel.LDAPError{Code: 50},
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
				options := admodel.ObjectMutationOptions{}
				if mode == "unsupported-assertion" {
					options.ExpectedVersion = &admodel.ObjectVersion{
						Source:     (*adengine.InternalClientConfigPointer(client)).Endpoint,
						GUID:       InternalObjectTestGUID(),
						USNChanged: 7,
					}
				}
				var result admodel.AccountExpirationMutationResult
				var err error
				if clear {
					result, err = adservice_accounts.New(client).
						ClearAccountExpiration(context.Background(), InternalObjectTestIdentity(), options)
				} else {
					result, err = adservice_accounts.New(client).
						SetAccountExpiration(context.Background(), admodel.SetAccountExpirationRequest{Identity: InternalObjectTestIdentity(), At: at, Options: options})
				}
				switch mode {
				case "accepted":
					if err != nil || writes != 1 || reads != 2 || !result.Mutation.Verified ||
						result.Expiration == nil ||
						*result.Expiration.Value != stamp {
						t.Fatal(result, err, reads, writes)
					}
				case "unsupported-assertion", "wrong-class":
					if err == nil || writes != 0 ||
						result.Mutation.State != admodel.ObjectWriteNotAttempted {
						t.Fatal(result, err)
					}
				case "uncertain":
					if !errors.Is(err, admodel.ErrObjectWriteUncertain) || writes != 1 ||
						reads != 1 ||
						result.Mutation.State != admodel.ObjectWriteUncertain {
						t.Fatal(result, err)
					}
				case "rejected":
					if !errors.Is(err, admodel.ErrObjectWritePermission) || writes != 1 ||
						reads != 1 ||
						result.Mutation.State != admodel.ObjectWriteRejected {
						t.Fatal(result, err)
					}
				default:
					if !errors.Is(err, admodel.ErrObjectVerification) ||
						result.Mutation.State != admodel.ObjectWriteAccepted ||
						result.Mutation.Verified ||
						writes != 1 {
						t.Fatal(result, err)
					}
				}
			})
		}
	}
}
