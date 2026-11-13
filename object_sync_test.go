package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"
)

type syncTestSession struct {
	testSession
	modify func(context.Context, string, []ldapModification) ldapWriteAttempt
	policy func(context.Context, string, string) (map[string][][]byte, error)
}

func (s *syncTestSession) ldapModify(c context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
	return s.modify(c, dn, mods)
}
func (s *syncTestSession) objectSyncPasswordPolicy(c context.Context, rodc, account string) (map[string][][]byte, error) {
	return s.policy(c, rodc, account)
}

const syncTestNC = "DC=example,DC=test"
const syncTestConfig = "CN=Configuration," + syncTestNC
const syncTestObject = "CN=Dŵr:SECRETS_ONLY,OU=Objects," + syncTestNC
const syncTestSource = "CN=NTDS Settings,CN=Source,CN=Servers," + syncTestConfig
const syncTestTarget = "CN=NTDS Settings,CN=Target,CN=Servers," + syncTestConfig

type syncFixture struct {
	source, target                    *syncTestSession
	src, dst                          map[string]map[string][][]byte
	request                           SyncObjectRequest
	writes, policyCalls, sourceCloses int
	write                             ldapWriteAttempt
}

func newSyncFixture(t *testing.T) *syncFixture {
	t.Helper()
	f := &syncFixture{src: map[string]map[string][][]byte{}, dst: map[string]map[string][][]byte{}, write: ldapWriteAttempt{State: ldapWriteAccepted}}
	f.request = SyncObjectRequest{Source: Config{Endpoint: Endpoint{Host: "source.example.test"}, Timeout: time.Second}, Partition: syncTestNC, Object: SyncObjectIdentity{DistinguishedName: syncTestObject}, Properties: []string{"description"}}
	add := func(dn, class string, id byte, instance string) {
		guid := make([]byte, 16)
		guid[0] = id
		attrs := map[string][][]byte{"distinguishedname": {[]byte(dn)}, "objectguid": {guid}, "objectclass": {[]byte(class)}, "instancetype": {[]byte(instance)}}
		f.src[dn] = attrs
		f.dst[dn] = maps.Clone(attrs)
	}
	add(syncTestNC, "domainDNS", 1, "5")
	add(syncTestConfig, "configuration", 2, "5")
	add(syncTestSource, "nTDSDSA", 3, "4")
	add(syncTestTarget, "nTDSDSA", 4, "4")
	add("OU=Objects,"+syncTestNC, "organizationalUnit", 5, "4")
	add(syncTestObject, "user", 6, "4")
	f.src[syncTestObject]["description"] = [][]byte{[]byte("controlled change")}
	f.dst[syncTestObject]["description"] = [][]byte{[]byte("old value")}
	for _, objects := range []map[string]map[string][][]byte{f.src, f.dst} {
		for _, dn := range []string{syncTestSource, syncTestTarget} {
			objects[dn]["msds-isrodc"] = [][]byte{[]byte("FALSE")}
			objects[dn]["msds-hasmasterncs"] = [][]byte{[]byte(syncTestNC), []byte(syncTestConfig)}
		}
	}
	root := func(dsa string) map[string][][]byte {
		return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}, "supportedcontrol": {[]byte(objectSyncDNInputOID)}, "dsservicename": {[]byte(dsa)}, "configurationnamingcontext": {[]byte(syncTestConfig)}, "defaultnamingcontext": {[]byte(syncTestNC)}, "namingcontexts": {[]byte(syncTestNC), []byte(syncTestConfig)}, "issynchronized": {[]byte("TRUE")}}
	}
	f.src[""] = root(syncTestSource)
	f.dst[""] = root(syncTestTarget)
	reader := func(objects map[string]map[string][][]byte) func(context.Context, string, []string) (map[string][][]byte, error) {
		return func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
			if err := context.Cause(ctx); err != nil {
				return nil, err
			}
			if strings.HasPrefix(dn, "<GUID=") {
				for key, obj := range objects {
					if syncGUIDDN(syncGUID(Object{Attributes: obj})) == dn {
						dn = key
						break
					}
				}
			}
			obj, ok := objects[dn]
			if !ok {
				return nil, &LDAPError{Operation: "fixture", Code: 32}
			}
			out := map[string][][]byte{}
			for _, p := range properties {
				if v, ok := obj[strings.ToLower(p)]; ok {
					out[strings.ToLower(p)] = v
				}
			}
			return out, nil
		}
	}
	f.source = &syncTestSession{testSession: testSession{base: reader(f.src), finish: func() error { f.sourceCloses++; return nil }}}
	f.target = &syncTestSession{testSession: testSession{base: reader(f.dst), finish: func() error { return nil }}}
	f.target.modify = func(_ context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
		f.writes++
		want := syncGUIDDN(f.src[syncTestSource]["objectguid"][0]) + ":" + syncGUIDDN(f.src[syncTestObject]["objectguid"][0])
		if f.request.PasswordOnly {
			want += ":SECRETS_ONLY"
		}
		if dn != "" || len(mods) != 1 || mods[0].attribute != "replicateSingleObject" || mods[0].operation != 2 || string(mods[0].value) != want {
			t.Fatalf("unsafe/incorrect request: %q %+v", dn, mods)
		}
		if f.write.State == ldapWriteAccepted {
			f.dst[syncTestObject] = maps.Clone(f.src[syncTestObject])
		}
		return f.write
	}
	f.target.policy = func(_ context.Context, rodc, account string) (map[string][][]byte, error) {
		f.policyCalls++
		if rodc != syncGUIDDN(f.dst[syncTestTarget]["objectguid"][0]) || account != syncGUIDDN(f.src[syncTestObject]["objectguid"][0]) {
			t.Fatal("policy checked wrong identity")
		}
		return map[string][][]byte{"msds-isusercachableatrodc": {[]byte("1")}}, nil
	}
	return f
}

func (f *syncFixture) run() (SyncObjectResult, error) {
	client := newClient(Config{Timeout: time.Second}, f.target)
	defer client.Close()
	return client.syncObjectDial(context.Background(), f.request, func(context.Context, Config) (*Client, error) {
		return newClient(Config{Timeout: time.Second}, f.source), nil
	})
}

func TestSyncObjectRequestAndConvergence(t *testing.T) {
	for _, guidIdentity := range []bool{false, true} {
		f := newSyncFixture(t)
		if guidIdentity {
			f.request.Object = SyncObjectIdentity{ObjectGUID: f.src[syncTestObject]["objectguid"][0]}
		}
		result, err := f.run()
		if err != nil || !result.Verified || result.State != ObjectSyncAccepted || f.writes != 1 || f.sourceCloses != 1 || len(result.VerifiedProperties) != 1 {
			t.Fatalf("result=%+v error=%v writes=%d closes=%d", result, err, f.writes, f.sourceCloses)
		}
	}
}

func TestSyncObjectPreflightNeverWrites(t *testing.T) {
	for _, name := range []string{"missing-nc", "different-nc", "non-nc", "transition-nc", "missing-source", "deleted-source", "missing-parent", "different-parent", "same-dsa", "unknown-directory", "unsynchronized", "missing-property", "rodc-password-destination", "rodc-password-source", "password-lds", "denied-preflight", "nested-nc"} {
		t.Run(name, func(t *testing.T) {
			f := newSyncFixture(t)
			switch name {
			case "missing-nc":
				delete(f.dst, syncTestNC)
			case "different-nc":
				f.dst[syncTestNC]["objectguid"] = [][]byte{make([]byte, 16)}
			case "non-nc":
				f.dst[syncTestNC]["instancetype"] = [][]byte{[]byte("4")}
			case "transition-nc":
				f.dst[syncTestNC]["instancetype"] = [][]byte{[]byte("21")}
			case "missing-source":
				delete(f.src, syncTestObject)
			case "deleted-source":
				f.src[syncTestObject]["isdeleted"] = [][]byte{[]byte("TRUE")}
			case "missing-parent":
				delete(f.dst, "OU=Objects,"+syncTestNC)
			case "different-parent":
				f.dst["OU=Objects,"+syncTestNC]["objectguid"] = f.src[syncTestNC]["objectguid"]
			case "same-dsa":
				f.dst[""]["dsservicename"] = [][]byte{[]byte(syncTestSource)}
			case "unknown-directory":
				delete(f.src[""], "supportedcapabilities")
			case "unsynchronized":
				f.src[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "missing-property":
				delete(f.src[syncTestObject], "description")
			case "rodc-password-destination":
				f.request.PasswordOnly = true
				f.request.Properties = nil
			case "rodc-password-source":
				f.password()
				f.src[syncTestSource]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "password-lds":
				f.password()
				f.src[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
				f.dst[""]["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "denied-preflight":
				f.source.base = func(context.Context, string, []string) (map[string][][]byte, error) { return nil, &LDAPError{Code: 50} }
			case "nested-nc":
				f.src[""]["namingcontexts"] = append(f.src[""]["namingcontexts"], []byte("OU=Objects,"+syncTestNC))
			}
			result, err := f.run()
			if err == nil || f.writes != 0 || result.State != ObjectSyncNotAttempted {
				t.Fatalf("result=%+v err=%v writes=%d", result, err, f.writes)
			}
			if name == "denied-preflight" && !errors.Is(err, ErrObjectSyncPermission) {
				t.Fatal(err)
			}
		})
	}
}

func TestSyncObjectAcknowledgementAndNoReplay(t *testing.T) {
	for _, state := range []ldapWriteState{ldapWriteNotAttempted, ldapWriteRejected, ldapWriteUncertain, ldapWriteAccepted} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			f := newSyncFixture(t)
			failure := errors.New("transport or cleanup failure")
			f.write = ldapWriteAttempt{State: state, Err: failure}
			result, err := f.run()
			if !errors.Is(err, failure) || result.State != ObjectSyncWriteState(state) || f.writes != 1 {
				t.Fatalf("%+v %v writes=%d", result, err, f.writes)
			}
			if state == ldapWriteUncertain && !errors.Is(err, ErrObjectSyncUncertain) {
				t.Fatal(err)
			}
			if state == ldapWriteAccepted && !result.Verified {
				t.Fatal("lost accepted state/readback after cleanup error")
			}
		})
	}
	f := newSyncFixture(t)
	f.write = ldapWriteAttempt{State: ldapWriteRejected, Err: &LDAPError{Code: 50, Diagnostic: "private diagnostic"}}
	_, err := f.run()
	if !errors.Is(err, ErrObjectSyncPermission) || strings.Contains(err.Error(), "private diagnostic") {
		t.Fatal(err)
	}
}

func TestSyncObjectAcceptedReadbackFailures(t *testing.T) {
	for _, name := range []string{"mismatch", "inaccessible", "different-guid", "source-close"} {
		t.Run(name, func(t *testing.T) {
			f := newSyncFixture(t)
			modify := f.target.modify
			f.target.modify = func(ctx context.Context, dn string, mods []ldapModification) ldapWriteAttempt {
				a := modify(ctx, dn, mods)
				switch name {
				case "mismatch":
					f.dst[syncTestObject]["description"] = [][]byte{[]byte("concurrent destination write")}
				case "inaccessible":
					delete(f.dst, syncTestObject)
				case "different-guid":
					f.dst[syncTestObject]["objectguid"] = f.src[syncTestNC]["objectguid"]
				case "source-close":
					f.source.finish = func() error { return errors.New("close failure") }
				}
				return a
			}
			r, err := f.run()
			if err == nil || r.State != ObjectSyncAccepted || f.writes != 1 {
				t.Fatalf("%+v %v", r, err)
			}
			if name != "source-close" && (r.Verified || !errors.Is(err, ErrObjectSyncReadback)) {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func (f *syncFixture) password() {
	f.request.PasswordOnly = true
	f.request.Properties = nil
	f.dst[syncTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
	f.dst[syncTestTarget]["msds-hasfullreplicancs"] = [][]byte{[]byte(syncTestNC), []byte(syncTestConfig)}
	server, _ := parentDirectoryDN(syncTestTarget)
	computer := "CN=RODC," + syncTestNC
	f.dst[server] = map[string][][]byte{"serverreference": {[]byte(computer)}}
	f.dst[computer] = map[string][][]byte{"msds-revealedlist": {[]byte("S:10:unicodePwd:" + syncTestObject)}}
}

func TestSyncObjectPasswordOnly(t *testing.T) {
	for _, name := range []string{"allowed", "denied", "no-policy", "missing-policy", "permission", "no-control", "no-marker"} {
		t.Run(name, func(t *testing.T) {
			f := newSyncFixture(t)
			f.password()
			switch name {
			case "denied", "no-policy", "missing-policy":
				f.target.policy = func(context.Context, string, string) (map[string][][]byte, error) {
					v := "0"
					if name == "no-policy" {
						v = "2"
					}
					if name == "missing-policy" {
						return nil, nil
					}
					return map[string][][]byte{"msds-isusercachableatrodc": {[]byte(v)}}, nil
				}
			case "permission":
				f.target.policy = func(context.Context, string, string) (map[string][][]byte, error) { return nil, &LDAPError{Code: 50} }
			case "no-control":
				delete(f.dst[""], "supportedcontrol")
			case "no-marker":
				delete(f.dst["CN=RODC,"+syncTestNC], "msds-revealedlist")
			}
			r, err := f.run()
			if name == "allowed" {
				if err != nil || !r.Verified || !r.SecretCacheObserved || f.writes != 1 || f.policyCalls != 1 {
					t.Fatalf("%+v %v", r, err)
				}
				return
			}
			if err == nil || r.Verified {
				t.Fatalf("%+v %v", r, err)
			}
			wantWrites := 0
			if name == "no-marker" {
				wantWrites = 1
			}
			if f.writes != wantWrites {
				t.Fatal(f.writes)
			}
		})
	}
}

func TestSyncObjectPortableValidationAndUnreachableSource(t *testing.T) {
	f := newSyncFixture(t)
	for _, change := range []func(*SyncObjectRequest){
		func(r *SyncObjectRequest) { r.Source.Endpoint.Host = "" }, func(r *SyncObjectRequest) { r.Partition = "" }, func(r *SyncObjectRequest) { r.Object = SyncObjectIdentity{} }, func(r *SyncObjectRequest) { r.Object.ObjectGUID = make([]byte, 16) }, func(r *SyncObjectRequest) { r.Object = SyncObjectIdentity{ObjectGUID: []byte{1}} }, func(r *SyncObjectRequest) { r.Properties = []string{"*"} }, func(r *SyncObjectRequest) { r.Properties = []string{"member;range=0-*"} }, func(r *SyncObjectRequest) { r.PasswordOnly = true },
	} {
		r := f.request
		change(&r)
		if r.Validate() == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	c := newClient(Config{Timeout: time.Second}, f.target)
	defer c.Close()
	unreachable := &LDAPError{Code: 81}
	r, err := c.syncObjectDial(context.Background(), f.request, func(context.Context, Config) (*Client, error) { return nil, unreachable })
	if !errors.Is(err, unreachable) || f.writes != 0 || r.State != ObjectSyncNotAttempted {
		t.Fatalf("%+v %v", r, err)
	}
}
