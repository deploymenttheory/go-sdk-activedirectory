package activedirectory

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

func accountStateTime(t *testing.T, text string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestAccountExpirationSentinelsAndPrecision(t *testing.T) {
	for _, raw := range []string{"0", "9223372036854775807", "133802606451234567", "-1", "not-a-time"} {
		object := accountTestEntry(512)
		object.Attributes["accountexpires"] = [][]byte{[]byte(raw)}
		result, err := decodeAccountExpiration(object)
		switch raw {
		case "0", "9223372036854775807":
			if err != nil || result.Value == nil || result.NeverExpires == nil || !*result.NeverExpires || result.ExpiresAt != nil {
				t.Fatal(result, err)
			}
		case "133802606451234567":
			if err != nil || result.NeverExpires == nil || *result.NeverExpires || result.ExpiresAt == nil || result.ExpiresAt.Nanosecond() != 123456700 {
				t.Fatal(result, err)
			}
		default:
			if err == nil || result.NeverExpires != nil {
				t.Fatal(result, err)
			}
		}
	}
	result, err := decodeAccountExpiration(accountTestEntry(512))
	if err != nil || result.Value != nil || result.NeverExpires != nil {
		t.Fatal(result, err)
	}
	utc := accountStateTime(t, "2026-11-13T11:22:33.1234567Z")
	local := accountStateTime(t, "2026-11-13T12:22:33.1234567+01:00")
	a, err := finiteAccountTime(utc)
	b, other := finiteAccountTime(local)
	if err != nil || other != nil || a != b {
		t.Fatal(a, b, err, other)
	}
	for _, bad := range []time.Time{time.Time{}, time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC), utc.Add(time.Nanosecond), time.Date(1600, 12, 31, 23, 59, 59, 0, time.UTC)} {
		if _, err := finiteAccountTime(bad); !errors.Is(err, ErrInvalidAccountExpiration) {
			t.Fatal(bad, err)
		}
	}
}

func TestAccountExpirationReadClassAndVisibility(t *testing.T) {
	for _, kind := range []string{CapabilityActiveDirectory, CapabilityADLDS} {
		for _, mode := range []string{"never", "hidden", "wrong-class"} {
			t.Run(kind+mode, func(t *testing.T) {
				client := objectTestClient(t, nil, func(_ context.Context, query SearchOptions) (searchCursor, error) {
					if !slices.Contains(query.Properties, "accountExpires") {
						t.Fatal(query)
					}
					object := accountTestEntry(512)
					if mode == "never" {
						object.Attributes["accountexpires"] = [][]byte{[]byte("0")}
					}
					if mode == "wrong-class" {
						object.Attributes["objectclass"] = [][]byte{[]byte("group")}
					}
					return objectTestCursor(object), nil
				}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
					t.Fatal("read wrote")
					return ldapWriteAttempt{}
				})
				session := client.session.(objectWriteTestSession)
				session.read = func(context.Context, []string) (map[string][][]byte, error) { return identityTestRoot(kind), nil }
				client.session = session
				result, err := client.AccountExpiration(context.Background(), objectTestIdentity(), ResolveIdentityOptions{})
				if mode == "wrong-class" {
					if !errors.Is(err, ErrAccountControlTarget) || result.Expiration != nil {
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
				at := accountStateTime(t, "2026-11-13T11:22:33.1234567Z")
				stamp, _ := finiteAccountTime(at)
				if clear {
					stamp = math.MaxInt64
				}
				reads, writes := 0, 0
				client := objectTestClient(t, nil, func(context.Context, SearchOptions) (searchCursor, error) {
					reads++
					object := accountTestEntry(512)
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
					return objectTestCursor(object), nil
				}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
					writes++
					if request.operation != ldapWriteModify || request.dn != objectGUIDTarget(objectTestGUID()) || len(request.modifications) != 1 || request.modifications[0].operation != 2 || request.modifications[0].attribute != "accountExpires" || string(request.modifications[0].values[0]) != stamp.LDAPString() {
						t.Fatal(request)
					}
					if mode == "rejected" {
						return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}
					}
					if mode == "uncertain" {
						return ldapWriteAttempt{State: ldapWriteUncertain, Err: context.DeadlineExceeded}
					}
					return ldapWriteAttempt{State: ldapWriteAccepted}
				})
				options := ObjectMutationOptions{}
				if mode == "unsupported-assertion" {
					options.ExpectedVersion = &ObjectVersion{Source: client.config.Endpoint, GUID: objectTestGUID(), USNChanged: 7}
				}
				var result AccountExpirationMutationResult
				var err error
				if clear {
					result, err = client.ClearAccountExpiration(context.Background(), objectTestIdentity(), options)
				} else {
					result, err = client.SetAccountExpiration(context.Background(), SetAccountExpirationRequest{Identity: objectTestIdentity(), At: at, Options: options})
				}
				switch mode {
				case "accepted":
					if err != nil || writes != 1 || reads != 2 || !result.Mutation.Verified || result.Expiration == nil || *result.Expiration.Value != stamp {
						t.Fatal(result, err, reads, writes)
					}
				case "unsupported-assertion", "wrong-class":
					if err == nil || writes != 0 || result.Mutation.State != ObjectWriteNotAttempted {
						t.Fatal(result, err)
					}
				case "uncertain":
					if !errors.Is(err, ErrObjectWriteUncertain) || writes != 1 || reads != 1 || result.Mutation.State != ObjectWriteUncertain {
						t.Fatal(result, err)
					}
				case "rejected":
					if !errors.Is(err, ErrObjectWritePermission) || writes != 1 || reads != 1 || result.Mutation.State != ObjectWriteRejected {
						t.Fatal(result, err)
					}
				default:
					if !errors.Is(err, ErrObjectVerification) || result.Mutation.State != ObjectWriteAccepted || result.Mutation.Verified || writes != 1 {
						t.Fatal(result, err)
					}
				}
			})
		}
	}
}
