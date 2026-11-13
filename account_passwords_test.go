package activedirectory

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

type passwordTestSession struct {
	objectWriteTestSession
	protect func(context.Context, Transport) (PasswordProtection, error)
}

func (s passwordTestSession) passwordProtection(ctx context.Context, transport Transport) (PasswordProtection, error) {
	return s.protect(ctx, transport)
}

func passwordTestClient(t *testing.T, kind string, protect func(context.Context, Transport) (PasswordProtection, error), search func(context.Context, SearchOptions) (searchCursor, error), write func(context.Context, ldapWriteRequest) ldapWriteAttempt) *Client {
	t.Helper()
	client := newClient(Config{Endpoint: Endpoint{Host: "dc.example", Port: 389}, Timeout: time.Second}, passwordTestSession{objectWriteTestSession: objectWriteTestSession{testSession: testSession{base: func(_ context.Context, base string, _ []string) (map[string][][]byte, error) {
		if base != "" {
			return map[string][][]byte{"msds-isrodc": {[]byte("FALSE")}}, nil
		}
		root := identityTestRoot(kind)
		root["dsservicename"] = [][]byte{[]byte("CN=NTDS Settings,CN=DC,CN=Configuration,DC=example")}
		return root, nil
	}, search: search, finish: func() error { return nil }}, write: write}, protect: protect})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	return client
}
func passwordTestProtection(_ context.Context, transport Transport) (PasswordProtection, error) {
	return PasswordProtection{Transport: transport, CipherBits: 128}, nil
}
func passwordTestSearch(_ context.Context, query SearchOptions) (searchCursor, error) {
	entry := objectTestEntry("CN=sample,DC=example")
	entry.Attributes["objectclass"] = [][]byte{[]byte("top"), []byte("user")}
	return objectTestCursor(entry), nil
}

func TestPasswordEncodingUnicodeQuotesAndEmpty(t *testing.T) {
	for _, tc := range []struct{ value, want string }{{"new", "22006e00650077002200"}, {"李😀\"", "22004e673dd800de22002200"}, {"", "22002200"}} {
		want, _ := hex.DecodeString(tc.want)
		if got := quotedPasswordUTF16([]byte(tc.value)); !bytes.Equal(got, want) {
			t.Fatal("quoted UTF-16LE differs from public fixture")
		}
	}
	for _, value := range [][]byte{nil, {0}, {0xff}, {0xed, 0xa0, 0x80}} {
		if !errors.Is(validatePasswordBytes(value), ErrInvalidPasswordRequest) {
			t.Fatal("accepted omitted/invalid password")
		}
	}
	if err := validatePasswordBytes([]byte{}); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordRequestsRedactFormattingAndSerialization(t *testing.T) {
	for _, request := range []any{PasswordChangeRequest{OldPassword: []byte("PUBLIC-OLD"), NewPassword: []byte("PUBLIC-NEW")}, PasswordResetRequest{NewPassword: []byte("PUBLIC-NEW")}} {
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
		client := passwordTestClient(t, CapabilityActiveDirectory, func(ctx context.Context, transport Transport) (PasswordProtection, error) {
			protections++
			return passwordTestProtection(ctx, transport)
		}, func(ctx context.Context, query SearchOptions) (searchCursor, error) {
			reads++
			for _, name := range query.Properties {
				if name == "unicodePwd" {
					t.Fatal("password readback requested")
				}
			}
			return passwordTestSearch(ctx, query)
		}, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
			writes++
			if request.operation != ldapWriteModify || request.dn != "<GUID=33221100554477668899aabbccddeeff>" || len(request.controls) != 0 {
				t.Fatal("wrong password write target")
			}
			if change {
				if len(request.modifications) != 2 || request.modifications[0].operation != 1 || request.modifications[1].operation != 0 || !bytes.Equal(request.modifications[0].values[0], quotedPasswordUTF16(oldPassword)) {
					t.Fatal("password change operations differ")
				}
			} else if len(request.modifications) != 1 || request.modifications[0].operation != 2 {
				t.Fatal("password reset must be one replace")
			}
			for _, mod := range request.modifications {
				if mod.attribute != "unicodePwd" || len(mod.values) != 1 {
					t.Fatal("unexpected password attribute")
				}
				nativeBuffers = append(nativeBuffers, mod.values[0])
			}
			if !bytes.Equal(nativeBuffers[len(nativeBuffers)-1], quotedPasswordUTF16(newPassword)) {
				t.Fatal("new password encoding differs")
			}
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		var result PasswordResult
		var err error
		if change {
			result, err = client.ChangeAccountPassword(context.Background(), PasswordChangeRequest{Identity: objectTestIdentity(), OldPassword: oldPassword, NewPassword: newPassword})
		} else {
			result, err = client.ResetAccountPassword(context.Background(), PasswordResetRequest{Identity: objectTestIdentity(), NewPassword: newPassword})
		}
		if err != nil || result.State != ObjectWriteAccepted || result.TargetGUID == nil || writes != 1 || reads != 1 || protections != 2 {
			t.Fatalf("state=%d reads=%d writes=%d checks=%d err=%v", result.State, reads, writes, protections, err)
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
		name    string
		attempt ldapWriteAttempt
		want    error
		state   ObjectWriteState
	}{
		{"wrong old", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 49, Diagnostic: "00000056: public synthetic detail"}}, ErrPasswordCredential, ObjectWriteRejected},
		{"policy", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 19, Diagnostic: "0000052D: public synthetic detail"}}, ErrPasswordConstraint, ObjectWriteRejected},
		{"access", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50}}, ErrPasswordAccess, ObjectWriteRejected},
		{"unwilling ambiguous", ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 53}}, nil, ObjectWriteRejected},
		{"uncertain", ldapWriteAttempt{State: ldapWriteUncertain, Err: errLDAPWriteUncertain}, ErrPasswordUncertain, ObjectWriteUncertain},
		{"accepted cleanup", ldapWriteAttempt{State: ldapWriteAccepted, Err: context.Canceled}, context.Canceled, ObjectWriteAccepted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writes := 0
			var buffer []byte
			client := passwordTestClient(t, CapabilityActiveDirectory, passwordTestProtection, passwordTestSearch, func(_ context.Context, request ldapWriteRequest) ldapWriteAttempt {
				writes++
				buffer = request.modifications[0].values[0]
				return tc.attempt
			})
			result, err := client.ResetAccountPassword(context.Background(), PasswordResetRequest{Identity: objectTestIdentity(), NewPassword: []byte("PUBLIC-test")})
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || result.State != tc.state || writes != 1 || !bytes.Equal(buffer, make([]byte, len(buffer))) {
				t.Fatalf("state=%d writes=%d err=%v", result.State, writes, err)
			}
			var native *LDAPError
			if errors.As(tc.attempt.Err, &native) {
				var returned *LDAPError
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
			kind := CapabilityActiveDirectory
			if mode == "LDS SID" || mode == "LDS account name" {
				kind = CapabilityADLDS
			}
			if mode == "unknown" {
				kind = "unknown"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := passwordTestClient(t, kind, func(ctx context.Context, transport Transport) (PasswordProtection, error) {
				checks++
				if mode == "insecure" || (mode == "downgraded" && checks == 2) {
					return PasswordProtection{}, ErrPasswordProtection
				}
				if mode == "weak" {
					return PasswordProtection{Transport: transport, CipherBits: 56}, nil
				}
				return passwordTestProtection(ctx, transport)
			}, func(ctx context.Context, query SearchOptions) (searchCursor, error) {
				if mode == "wrong class" {
					entry := objectTestEntry("CN=sample,DC=example")
					entry.Attributes["objectclass"] = [][]byte{[]byte("container")}
					return objectTestCursor(entry), nil
				}
				return passwordTestSearch(ctx, query)
			}, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
				writes++
				return ldapWriteAttempt{State: ldapWriteAccepted}
			})
			account := objectTestIdentity()
			if mode == "scope" {
				account, _ = IdentityByDN("CN=sample,DC=other")
			}
			if mode == "LDS SID" {
				account, _ = IdentityBySID("S-1-5-21-42")
			}
			if mode == "LDS account name" {
				account, _ = IdentityByAccountName("sample")
			}
			if mode == "canceled" {
				cancel()
			}
			result, err := client.ResetAccountPassword(ctx, PasswordResetRequest{Identity: account, NewPassword: []byte("PUBLIC-test")})
			if err == nil || writes != 0 || result.State != ObjectWriteNotAttempted {
				t.Fatalf("state=%d writes=%d err=%v", result.State, writes, err)
			}
		})
	}
	// LDS user objects need not expose objectSid and may use arbitrary ports.
	client := passwordTestClient(t, CapabilityADLDS, passwordTestProtection, passwordTestSearch, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
		return ldapWriteAttempt{State: ldapWriteAccepted}
	})
	client.config.Endpoint.Port = 3268
	if result, err := client.ResetAccountPassword(context.Background(), PasswordResetRequest{Identity: objectTestIdentity(), NewPassword: []byte("PUBLIC-test")}); err != nil || result.State != ObjectWriteAccepted {
		t.Fatal(result.State, err)
	}
}

func TestPasswordRODCAndMissingWritableEvidenceReject(t *testing.T) {
	for _, mode := range []string{"RODC", "hidden", "malformed", "GC"} {
		writes := 0
		client := passwordTestClient(t, CapabilityActiveDirectory, passwordTestProtection, passwordTestSearch, func(context.Context, ldapWriteRequest) ldapWriteAttempt {
			writes++
			return ldapWriteAttempt{State: ldapWriteAccepted}
		})
		session := client.session.(passwordTestSession)
		base := session.base
		session.base = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
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
		client.session = session
		if mode == "GC" {
			client.config.Endpoint.Port = 3268
		}
		result, err := client.ResetAccountPassword(context.Background(), PasswordResetRequest{Identity: objectTestIdentity(), NewPassword: []byte("PUBLIC-test")})
		if err == nil || writes != 0 || result.State != ObjectWriteNotAttempted {
			t.Fatal(mode, result.State, err)
		}
	}
}
