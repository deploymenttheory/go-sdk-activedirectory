package activedirectory

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type passwordPolicyTestSession struct {
	testSession
	modify func(context.Context, string, []ldapModification) ldapWriteAttempt
}

func (s passwordPolicyTestSession) ldapModify(ctx context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
	return s.modify(ctx, dn, mods)
}

func policyPointer[T any](value T) *T { return &value }

func passwordPolicyFixture() map[string]map[string][][]byte {
	objects, _, _ := operationMasterFixture()
	policy := objects[operationTestDomain]
	for key, value := range map[string]string{
		"instancetype": "5", "maxpwdage": "-36288000000000", "minpwdage": "-864000000000",
		"lockoutduration": "-18000000000", "lockoutobservationwindow": "-6000000000",
		"lockoutthreshold": "5", "minpwdlength": "12", "pwdhistorylength": "24", "pwdproperties": "63", "uascompat": "1",
	} {
		policy[key] = [][]byte{[]byte(value)}
	}
	return objects
}

func passwordPolicyClient(objects map[string]map[string][][]byte, modify func(context.Context, string, []ldapModification) ldapWriteAttempt) *Client {
	return newClient(Config{Timeout: time.Second}, passwordPolicyTestSession{
		testSession: testSession{
			base: func(ctx context.Context, dn string, _ []string) (map[string][][]byte, error) {
				if err := context.Cause(ctx); err != nil {
					return nil, err
				}
				if value, ok := objects[dn]; ok {
					return value, nil
				}
				return nil, &LDAPError{Code: 32, Operation: "test read"}
			}, finish: func() error { return nil },
		}, modify: modify,
	})
}

// Model LDAP Modify's exact-value delete and atomic failure, rather than
// letting a fake unconditional replacement conceal lost-update mistakes.
func applyPolicyTestModify(objects map[string]map[string][][]byte, dn string, mods []ldapModification) ldapWriteAttempt {
	staged := make(map[string][][]byte)
	for key, values := range objects[dn] {
		staged[key] = values
	}
	for _, mod := range mods {
		key := strings.ToLower(mod.attribute)
		switch mod.operation {
		case 1:
			if len(staged[key]) != 1 || string(staged[key][0]) != string(mod.value) {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 16, Operation: "conditional modify"}}
			}
			delete(staged, key)
		case 0:
			if len(staged[key]) != 0 {
				return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 20}}
			}
			staged[key] = [][]byte{mod.value}
		default:
			return ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 53}}
		}
	}
	objects[dn] = staged
	return ldapWriteAttempt{State: ldapWriteAccepted}
}

func TestPasswordPolicyReadAndIntervals(t *testing.T) {
	objects := passwordPolicyFixture()
	client := passwordPolicyClient(objects, nil)
	policy, err := client.DefaultDomainPasswordPolicy(context.Background())
	if err != nil || policy.DomainDN != operationTestDomain || policy.MaxPasswordAge != 36288000000000 || policy.MinPasswordAge != 864000000000 || policy.LockoutDuration != 18000000000 || policy.LockoutObservationWindow != 6000000000 || policy.LockoutThreshold != 5 || policy.MinPasswordLength != 12 || policy.PasswordHistoryCount != 24 || !policy.ComplexityEnabled() || !policy.ReversibleEncryptionEnabled() || policy.PasswordProperties != 63 || !policy.UASCompatible {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	for _, test := range []struct {
		raw     string
		want    PolicyInterval
		invalid bool
	}{
		{"0", 0, false}, {"-1", 1, false}, {"-9223372036854775807", PolicyNever - 1, false}, {"-9223372036854775808", PolicyNever, false},
		{"1", 0, true}, {"-9223372036854775809", 0, true}, {"invalid", 0, true},
	} {
		objects[operationTestDomain]["maxpwdage"] = [][]byte{[]byte(test.raw)}
		got, err := client.DefaultDomainPasswordPolicy(context.Background())
		if (err != nil) != test.invalid || got.MaxPasswordAge != test.want {
			t.Fatalf("%s -> %v, %v", test.raw, got.MaxPasswordAge, err)
		}
		if !test.invalid && formatPolicyInterval(got.MaxPasswordAge) != test.raw {
			t.Fatal("interval did not round trip")
		}
	}
	interval, err := PolicyIntervalFromDuration(90 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	duration, err := interval.Duration()
	if err != nil || duration != 90*time.Minute {
		t.Fatalf("duration=%v err=%v", duration, err)
	}
	for _, value := range []time.Duration{-100, 1, 101} {
		if _, err := PolicyIntervalFromDuration(value); !errors.Is(err, ErrPolicyIntervalRange) {
			t.Fatal("silently rounded", value)
		}
	}
	for _, value := range []PolicyInterval{PolicyNever, PolicyNever - 1, PolicyInterval(math.MaxInt64/100) + 1} {
		if _, err := value.Duration(); !errors.Is(err, ErrPolicyIntervalRange) {
			t.Fatal("silently overflowed", value)
		}
	}
}

func TestPasswordPolicyPatchPreservesOmissionsAndUnknownBits(t *testing.T) {
	objects := passwordPolicyFixture()
	// Include an unknown high bit with LDAP's signed INTEGER representation.
	objects[operationTestDomain]["pwdproperties"] = [][]byte{[]byte("-2147483585")}
	var submitted []ldapModification
	calls := 0
	client := passwordPolicyClient(objects, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
		calls++
		if dn != operationTestDomain {
			t.Fatal("wrong domain", dn)
		}
		submitted = mods
		return applyPolicyTestModify(objects, dn, mods)
	})
	zeroAge, zeroCount, disabled := PolicyInterval(0), uint16(0), false
	result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{MaxPasswordAge: &zeroAge, LockoutThreshold: &zeroCount, PasswordHistoryCount: &zeroCount, ComplexityEnabled: &disabled, ReversibleEncryptionEnabled: &disabled})
	if err != nil || calls != 1 || !result.Verified || result.WriteState != PasswordPolicyWriteAccepted || result.After.MaxPasswordAge != PolicyNever || result.After.LockoutThreshold != 0 || result.After.PasswordHistoryCount != 0 || result.After.PasswordProperties != 0x8000002e {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
	}
	if result.After.MinPasswordAge != result.Before.MinPasswordAge || result.After.MinPasswordLength != result.Before.MinPasswordLength || result.After.LockoutDuration != result.Before.LockoutDuration {
		t.Fatal("omitted fields changed")
	}
	want := []ldapModification{
		{1, "maxPwdAge", []byte("-36288000000000")}, {0, "maxPwdAge", []byte("-9223372036854775808")},
		{1, "lockoutThreshold", []byte("5")}, {0, "lockoutThreshold", []byte("0")},
		{1, "pwdHistoryLength", []byte("24")}, {0, "pwdHistoryLength", []byte("0")},
		{1, "pwdProperties", []byte("-2147483585")}, {0, "pwdProperties", []byte("-2147483602")},
	}
	if !reflect.DeepEqual(submitted, want) {
		t.Fatalf("mods=%+v want=%+v", submitted, want)
	}
}

func TestPasswordPolicyUpdateAllFieldsAndNoop(t *testing.T) {
	objects := passwordPolicyFixture()
	objects[operationTestDomain]["uascompat"] = [][]byte{[]byte("0")}
	objects[operationTestDomain]["pwdproperties"] = [][]byte{[]byte("32")}
	calls := 0
	client := passwordPolicyClient(objects, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
		calls++
		return applyPolicyTestModify(objects, dn, mods)
	})
	request := DomainPasswordPolicyUpdate{
		MaxPasswordAge: policyPointer(PolicyInterval(10000000)), MinPasswordAge: policyPointer(PolicyInterval(0)),
		LockoutDuration: policyPointer(PolicyNever), LockoutObservationWindow: policyPointer(PolicyInterval(100)),
		LockoutThreshold: policyPointer(uint16(65535)), MinPasswordLength: policyPointer(uint16(256)), PasswordHistoryCount: policyPointer(uint16(1024)),
		ComplexityEnabled: policyPointer(true), ReversibleEncryptionEnabled: policyPointer(true),
	}
	result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), request)
	if err != nil || !result.Verified || result.After.PasswordProperties != 49 || calls != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	result, err = client.UpdateDefaultDomainPasswordPolicy(context.Background(), request)
	if err != nil || !result.Verified || result.WriteState != PasswordPolicyWriteNotAttempted || calls != 1 {
		t.Fatal("no-op resubmitted a write", result, err)
	}
}

func TestPasswordPolicyConcurrentFlagEditFailsAtomicallyWithoutRetry(t *testing.T) {
	objects := passwordPolicyFixture()
	calls := 0
	client := passwordPolicyClient(objects, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
		calls++
		// Change an unrelated flag after the read. History precedes flags in
		// the request, so atomic failure must also preserve history.
		objects[dn]["pwdproperties"] = [][]byte{[]byte("127")}
		return applyPolicyTestModify(objects, dn, mods)
	})
	result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{ComplexityEnabled: policyPointer(false), PasswordHistoryCount: policyPointer(uint16(0))})
	if !errors.Is(err, ErrPasswordPolicyChanged) || result.WriteState != PasswordPolicyWriteRejected || calls != 1 || string(objects[operationTestDomain]["pwdproperties"][0]) != "127" || string(objects[operationTestDomain]["pwdhistorylength"][0]) != "24" {
		t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
	}
}

func TestPasswordPolicyTargetingAndReadOnly(t *testing.T) {
	for _, test := range []string{"lds", "unknown", "cross-domain", "application", "non-root", "wrong-dn", "rodc", "unsynchronized", "not-writable"} {
		t.Run(test, func(t *testing.T) {
			objects := passwordPolicyFixture()
			client := passwordPolicyClient(objects, func(context.Context, string, []ldapModification) ldapWriteAttempt {
				t.Fatal("invalid target reached write")
				return ldapWriteAttempt{}
			})
			switch test {
			case "lds":
				objects[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "unknown":
				delete(objects[""], "supportedcapabilities")
			case "cross-domain":
				client.config.Partition = "DC=other,DC=test"
			case "application":
				delete(objects[operationTestDomain], "objectsid")
			case "non-root":
				objects[operationTestDomain]["instancetype"] = [][]byte{[]byte("4")}
			case "wrong-dn":
				objects[operationTestDomain]["distinguishedname"] = [][]byte{[]byte("DC=other,DC=test")}
			case "rodc":
				objects[operationTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "unsynchronized":
				objects[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "not-writable":
				objects[operationTestDomain]["instancetype"] = [][]byte{[]byte("1")}
			}
			_, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{MinPasswordLength: policyPointer(uint16(13))})
			if err == nil {
				t.Fatal("accepted invalid update target")
			}
			_, readErr := client.DefaultDomainPasswordPolicy(context.Background())
			if test == "rodc" || test == "unsynchronized" || test == "not-writable" {
				if readErr != nil || !errors.Is(err, ErrPasswordPolicyReadOnly) {
					t.Fatalf("read=%v write=%v", readErr, err)
				}
			} else if readErr == nil {
				t.Fatal("read silently fell back to another domain")
			}
		})
	}
}

func TestPasswordPolicyValidationAndMalformedReads(t *testing.T) {
	for _, update := range []DomainPasswordPolicyUpdate{
		{}, {MinPasswordLength: policyPointer(uint16(257))}, {PasswordHistoryCount: policyPointer(uint16(1025))}, {MinPasswordAge: policyPointer(PolicyNever + 1)},
	} {
		if update.Validate() == nil {
			t.Fatalf("accepted %+v", update)
		}
	}
	for _, test := range []struct{ attr, value string }{
		{"minpwdlength", "-1"}, {"lockoutthreshold", "65536"}, {"pwdproperties", "4294967296"}, {"pwdproperties", "-2147483649"}, {"lockoutduration", "1"}, {"maxpwdage", "-9223372036854775809"}, {"pwdhistorylength", ""},
	} {
		objects := passwordPolicyFixture()
		objects[operationTestDomain][test.attr] = [][]byte{[]byte(test.value)}
		client := passwordPolicyClient(objects, nil)
		if _, err := client.DefaultDomainPasswordPolicy(context.Background()); err == nil {
			t.Fatalf("accepted %s=%s", test.attr, test.value)
		}
	}
	for _, update := range []DomainPasswordPolicyUpdate{
		{MinPasswordLength: policyPointer(uint16(15))},      // uASCompat is enabled.
		{LockoutDuration: policyPointer(PolicyInterval(1))}, // omitted window is larger.
		{LockoutObservationWindow: policyPointer(PolicyInterval(18000000001))},
	} {
		client := passwordPolicyClient(passwordPolicyFixture(), func(context.Context, string, []ldapModification) ldapWriteAttempt {
			t.Fatal("constraint reached write")
			return ldapWriteAttempt{}
		})
		if _, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), update); !errors.Is(err, ErrInvalidPasswordPolicy) {
			t.Fatal(err)
		}
	}
	for _, key := range passwordPolicyAttributes() {
		objects := passwordPolicyFixture()
		delete(objects[operationTestDomain], strings.ToLower(key))
		if _, err := passwordPolicyClient(objects, nil).DefaultDomainPasswordPolicy(context.Background()); err == nil {
			t.Fatal("missing required attribute accepted", key)
		}
	}
}

func TestPasswordPolicyWriteFailuresAndReadback(t *testing.T) {
	for _, test := range []struct {
		name    string
		state   ldapWriteState
		failure error
		want    error
	}{
		{"permission", ldapWriteRejected, &LDAPError{Code: 50, Diagnostic: "private", MatchedDN: operationTestDomain}, ErrPasswordPolicyPermission},
		{"unknown", ldapWriteUncertain, context.DeadlineExceeded, ErrPasswordPolicyUncertain},
		{"closed", ldapWriteNotAttempted, ErrClosed, ErrClosed},
		{"readback-mismatch", ldapWriteAccepted, nil, ErrPasswordPolicyReadback},
		{"readback-denied", ldapWriteAccepted, nil, ErrPasswordPolicyReadback},
	} {
		t.Run(test.name, func(t *testing.T) {
			objects := passwordPolicyFixture()
			calls := 0
			client := passwordPolicyClient(objects, func(context.Context, string, []ldapModification) ldapWriteAttempt {
				calls++
				if test.name == "readback-denied" {
					delete(objects, operationTestDomain)
				}
				return ldapWriteAttempt{State: test.state, Err: test.failure}
			})
			result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{MinPasswordLength: policyPointer(uint16(13))})
			if !errors.Is(err, test.want) || calls != 1 || result.Verified || result.WriteState != PasswordPolicyWriteState(test.state) {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
			if errors.Is(err, ErrOperationMasterUncertain) {
				t.Fatal("leaked another feature's error")
			}
			if test.name == "permission" {
				var ldapErr *LDAPError
				if !errors.As(err, &ldapErr) || ldapErr.Diagnostic != "private" {
					t.Fatal("lost LDAP details")
				}
			}
		})
	}
}

func TestPasswordPolicyPositiveFlagsPreserved(t *testing.T) {
	// Accept either common LDAP integer rendering while retaining the bitmask.
	for _, raw := range []string{"4294967295", "-1"} {
		objects := passwordPolicyFixture()
		objects[operationTestDomain]["pwdproperties"] = [][]byte{[]byte(raw)}
		client := passwordPolicyClient(objects, func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
			return applyPolicyTestModify(objects, dn, mods)
		})
		result, err := client.UpdateDefaultDomainPasswordPolicy(context.Background(), DomainPasswordPolicyUpdate{ComplexityEnabled: policyPointer(false)})
		if err != nil || result.After.PasswordProperties != math.MaxUint32-1 {
			t.Fatalf("raw=%s result=%+v err=%v", raw, result, err)
		}
		if string(objects[operationTestDomain]["pwdproperties"][0]) != strconv.FormatInt(-2, 10) {
			t.Fatal("new signed integer wire value incorrect")
		}
	}
}
