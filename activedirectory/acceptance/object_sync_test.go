package acceptance

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalSyncTestSession struct {
	InternalTestSession
	InternalModify func(context.Context, string, []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt
	InternalPolicy func(context.Context, string, string) (map[string][][]byte, error)
}

func (s *InternalSyncTestSession) InternalLdapModify(
	c context.Context,
	dn string,
	mods []admodel.InternalLdapModification,
) admodel.InternalLdapWriteAttempt {
	return s.InternalModify(c, dn, mods)
}

func (s *InternalSyncTestSession) InternalObjectSyncPasswordPolicy(
	c context.Context,
	rodc, account string,
) (map[string][][]byte, error) {
	return s.InternalPolicy(c, rodc, account)
}

const (
	InternalSyncTestNC     = "DC=example,DC=test"
	InternalSyncTestConfig = "CN=Configuration," + InternalSyncTestNC
	InternalSyncTestObject = "CN=Dŵr:SECRETS_ONLY,OU=Objects," + InternalSyncTestNC
	InternalSyncTestSource = "CN=NTDS Settings,CN=Source,CN=Servers," + InternalSyncTestConfig
	InternalSyncTestTarget = "CN=NTDS Settings,CN=Target,CN=Servers," + InternalSyncTestConfig
)

type InternalSyncFixture struct {
	InternalSource, InternalTarget                            *InternalSyncTestSession
	InternalSrc, InternalDst                                  map[string]map[string][][]byte
	InternalRequest                                           admodel.SyncObjectRequest
	InternalWrites, InternalPolicyCalls, InternalSourceCloses int
	InternalWrite                                             admodel.InternalLdapWriteAttempt
}

func InternalNewSyncFixture(t *testing.T) *InternalSyncFixture {
	t.Helper()
	f := &InternalSyncFixture{
		InternalSrc:   map[string]map[string][][]byte{},
		InternalDst:   map[string]map[string][][]byte{},
		InternalWrite: admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted},
	}
	f.InternalRequest = admodel.SyncObjectRequest{
		Source: admodel.Config{
			Endpoint: admodel.Endpoint{Host: "source.example.test"},
			Timeout:  time.Second,
		},
		Partition:  InternalSyncTestNC,
		Object:     admodel.SyncObjectIdentity{DistinguishedName: InternalSyncTestObject},
		Properties: []string{"description"},
	}
	add := func(dn, class string, id byte, instance string) {
		guid := make([]byte, 16)
		guid[0] = id
		attrs := map[string][][]byte{
			"distinguishedname": {[]byte(dn)},
			"objectguid":        {guid},
			"objectclass":       {[]byte(class)},
			"instancetype":      {[]byte(instance)},
		}
		f.InternalSrc[dn] = attrs
		f.InternalDst[dn] = maps.Clone(attrs)
	}
	add(InternalSyncTestNC, "domainDNS", 1, "5")
	add(InternalSyncTestConfig, "configuration", 2, "5")
	add(InternalSyncTestSource, "nTDSDSA", 3, "4")
	add(InternalSyncTestTarget, "nTDSDSA", 4, "4")
	add("OU=Objects,"+InternalSyncTestNC, "organizationalUnit", 5, "4")
	add(InternalSyncTestObject, "user", 6, "4")
	f.InternalSrc[InternalSyncTestObject]["description"] = [][]byte{[]byte("controlled change")}
	f.InternalDst[InternalSyncTestObject]["description"] = [][]byte{[]byte("old value")}
	for _, objects := range []map[string]map[string][][]byte{f.InternalSrc, f.InternalDst} {
		for _, dn := range []string{InternalSyncTestSource, InternalSyncTestTarget} {
			objects[dn]["msds-isrodc"] = [][]byte{[]byte("FALSE")}
			objects[dn]["msds-hasmasterncs"] = [][]byte{
				[]byte(InternalSyncTestNC),
				[]byte(InternalSyncTestConfig),
			}
		}
	}
	root := func(dsa string) map[string][][]byte {
		return map[string][][]byte{
			"supportedcapabilities":      {[]byte(admodel.CapabilityActiveDirectory)},
			"supportedcontrol":           {[]byte(admodel.InternalObjectSyncDNInputOID)},
			"dsservicename":              {[]byte(dsa)},
			"configurationnamingcontext": {[]byte(InternalSyncTestConfig)},
			"defaultnamingcontext":       {[]byte(InternalSyncTestNC)},
			"namingcontexts": {
				[]byte(InternalSyncTestNC),
				[]byte(InternalSyncTestConfig),
			},
			"issynchronized": {[]byte("TRUE")},
		}
	}
	f.InternalSrc[""] = root(InternalSyncTestSource)
	f.InternalDst[""] = root(InternalSyncTestTarget)
	reader := func(objects map[string]map[string][][]byte) func(context.Context, string, []string) (map[string][][]byte, error) {
		return func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
			if err := context.Cause(ctx); err != nil {
				return nil, err
			}
			if strings.HasPrefix(dn, "<GUID=") {
				for key, obj := range objects {
					if admodel.InternalSyncGUIDDN(
						admodel.InternalSyncGUID(admodel.Object{Attributes: obj}),
					) == dn {
						dn = key
						break
					}
				}
			}
			obj, ok := objects[dn]
			if !ok {
				return nil, &admodel.LDAPError{Operation: "fixture", Code: 32}
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
	f.InternalSource = &InternalSyncTestSession{
		InternalTestSession: InternalTestSession{
			InternalBase:   reader(f.InternalSrc),
			InternalFinish: func() error { f.InternalSourceCloses++; return nil },
		},
	}
	f.InternalTarget = &InternalSyncTestSession{
		InternalTestSession: InternalTestSession{
			InternalBase:   reader(f.InternalDst),
			InternalFinish: func() error { return nil },
		},
	}
	f.InternalTarget.InternalModify = func(_ context.Context, dn string, mods []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
		f.InternalWrites++
		want := admodel.InternalSyncGUIDDN(
			f.InternalSrc[InternalSyncTestSource]["objectguid"][0],
		) + ":" + admodel.InternalSyncGUIDDN(
			f.InternalSrc[InternalSyncTestObject]["objectguid"][0],
		)
		if f.InternalRequest.PasswordOnly {
			want += ":SECRETS_ONLY"
		}
		if dn != "" || len(mods) != 1 || mods[0].InternalAttribute != "replicateSingleObject" ||
			mods[0].InternalOperation != 2 ||
			string(mods[0].InternalValue) != want {
			t.Fatalf("unsafe/incorrect request: %q %+v", dn, mods)
		}
		if f.InternalWrite.State == admodel.InternalLdapWriteAccepted {
			f.InternalDst[InternalSyncTestObject] = maps.Clone(
				f.InternalSrc[InternalSyncTestObject],
			)
		}
		return f.InternalWrite
	}
	f.InternalTarget.InternalPolicy = func(_ context.Context, rodc, account string) (map[string][][]byte, error) {
		f.InternalPolicyCalls++
		if rodc != admodel.InternalSyncGUIDDN(
			f.InternalDst[InternalSyncTestTarget]["objectguid"][0],
		) ||
			account != admodel.InternalSyncGUIDDN(
				f.InternalSrc[InternalSyncTestObject]["objectguid"][0],
			) {
			t.Fatal("policy checked wrong identity")
		}
		return map[string][][]byte{"msds-isusercachableatrodc": {[]byte("1")}}, nil
	}
	return f
}

func (f *InternalSyncFixture) InternalRun() (admodel.SyncObjectResult, error) {
	client := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, f.InternalTarget)
	defer client.Close()
	return adengine.InternalClientSyncObjectDial(client,
		context.Background(),
		f.InternalRequest,
		func(context.Context, admodel.Config) (*adengine.Client, error) {
			return adengine.InternalNewClient(
				admodel.Config{Timeout: time.Second},
				f.InternalSource,
			), nil
		},
	)
}

func TestSyncObjectRequestAndConvergence(t *testing.T) {
	for _, guidIdentity := range []bool{false, true} {
		f := InternalNewSyncFixture(t)
		if guidIdentity {
			f.InternalRequest.Object = admodel.SyncObjectIdentity{
				ObjectGUID: f.InternalSrc[InternalSyncTestObject]["objectguid"][0],
			}
		}
		result, err := f.InternalRun()
		if err != nil || !result.Verified || result.State != admodel.ObjectSyncAccepted ||
			f.InternalWrites != 1 ||
			f.InternalSourceCloses != 1 ||
			len(result.VerifiedProperties) != 1 {
			t.Fatalf(
				"result=%+v error=%v writes=%d closes=%d",
				result,
				err,
				f.InternalWrites,
				f.InternalSourceCloses,
			)
		}
	}
}

func TestSyncObjectPreflightNeverWrites(t *testing.T) {
	for _, name := range []string{"missing-nc", "different-nc", "non-nc", "transition-nc", "missing-source", "deleted-source", "missing-parent", "different-parent", "same-dsa", "unknown-directory", "unsynchronized", "missing-property", "rodc-password-destination", "rodc-password-source", "password-lds", "denied-preflight", "nested-nc"} {
		t.Run(name, func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			switch name {
			case "missing-nc":
				delete(f.InternalDst, InternalSyncTestNC)
			case "different-nc":
				f.InternalDst[InternalSyncTestNC]["objectguid"] = [][]byte{make([]byte, 16)}
			case "non-nc":
				f.InternalDst[InternalSyncTestNC]["instancetype"] = [][]byte{[]byte("4")}
			case "transition-nc":
				f.InternalDst[InternalSyncTestNC]["instancetype"] = [][]byte{[]byte("21")}
			case "missing-source":
				delete(f.InternalSrc, InternalSyncTestObject)
			case "deleted-source":
				f.InternalSrc[InternalSyncTestObject]["isdeleted"] = [][]byte{[]byte("TRUE")}
			case "missing-parent":
				delete(f.InternalDst, "OU=Objects,"+InternalSyncTestNC)
			case "different-parent":
				f.InternalDst["OU=Objects,"+InternalSyncTestNC]["objectguid"] = f.InternalSrc[InternalSyncTestNC]["objectguid"]
			case "same-dsa":
				f.InternalDst[""]["dsservicename"] = [][]byte{[]byte(InternalSyncTestSource)}
			case "unknown-directory":
				delete(f.InternalSrc[""], "supportedcapabilities")
			case "unsynchronized":
				f.InternalSrc[""]["issynchronized"] = [][]byte{[]byte("FALSE")}
			case "missing-property":
				delete(f.InternalSrc[InternalSyncTestObject], "description")
			case "rodc-password-destination":
				f.InternalRequest.PasswordOnly = true
				f.InternalRequest.Properties = nil
			case "rodc-password-source":
				f.InternalPassword()
				f.InternalSrc[InternalSyncTestSource]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
			case "password-lds":
				f.InternalPassword()
				f.InternalSrc[""]["supportedcapabilities"] = [][]byte{
					[]byte(admodel.CapabilityADLDS),
				}
				f.InternalDst[""]["supportedcapabilities"] = [][]byte{
					[]byte(admodel.CapabilityADLDS),
				}
			case "denied-preflight":
				f.InternalSource.InternalBase = func(context.Context, string, []string) (map[string][][]byte, error) {
					return nil, &admodel.LDAPError{Code: 50}
				}
			case "nested-nc":
				f.InternalSrc[""]["namingcontexts"] = append(
					f.InternalSrc[""]["namingcontexts"],
					[]byte("OU=Objects,"+InternalSyncTestNC),
				)
			}
			result, err := f.InternalRun()
			if err == nil || f.InternalWrites != 0 ||
				result.State != admodel.ObjectSyncNotAttempted {
				t.Fatalf("result=%+v err=%v writes=%d", result, err, f.InternalWrites)
			}
			if name == "denied-preflight" && !errors.Is(err, admodel.ErrObjectSyncPermission) {
				t.Fatal(err)
			}
		})
	}
}

func TestSyncObjectAcknowledgementAndNoReplay(t *testing.T) {
	for _, state := range []admodel.InternalLdapWriteState{admodel.InternalLdapWriteNotAttempted, admodel.InternalLdapWriteRejected, admodel.InternalLdapWriteUncertain, admodel.InternalLdapWriteAccepted} {
		t.Run(fmt.Sprint(state), func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			failure := errors.New("transport or cleanup failure")
			f.InternalWrite = admodel.InternalLdapWriteAttempt{State: state, Err: failure}
			result, err := f.InternalRun()
			if !errors.Is(err, failure) || result.State != admodel.ObjectSyncWriteState(state) ||
				f.InternalWrites != 1 {
				t.Fatalf("%+v %v writes=%d", result, err, f.InternalWrites)
			}
			if state == admodel.InternalLdapWriteUncertain &&
				!errors.Is(err, admodel.ErrObjectSyncUncertain) {
				t.Fatal(err)
			}
			if state == admodel.InternalLdapWriteAccepted && !result.Verified {
				t.Fatal("lost accepted state/readback after cleanup error")
			}
		})
	}
	f := InternalNewSyncFixture(t)
	f.InternalWrite = admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteRejected,
		Err:   &admodel.LDAPError{Code: 50, Diagnostic: "private diagnostic"},
	}
	_, err := f.InternalRun()
	if !errors.Is(err, admodel.ErrObjectSyncPermission) ||
		strings.Contains(err.Error(), "private diagnostic") {
		t.Fatal(err)
	}
}

func TestSyncObjectAcceptedReadbackFailures(t *testing.T) {
	for _, name := range []string{"mismatch", "inaccessible", "different-guid", "source-close"} {
		t.Run(name, func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			modify := f.InternalTarget.InternalModify
			f.InternalTarget.InternalModify = func(ctx context.Context, dn string, mods []admodel.InternalLdapModification) admodel.InternalLdapWriteAttempt {
				a := modify(ctx, dn, mods)
				switch name {
				case "mismatch":
					f.InternalDst[InternalSyncTestObject]["description"] = [][]byte{
						[]byte("concurrent destination write"),
					}
				case "inaccessible":
					delete(f.InternalDst, InternalSyncTestObject)
				case "different-guid":
					f.InternalDst[InternalSyncTestObject]["objectguid"] = f.InternalSrc[InternalSyncTestNC]["objectguid"]
				case "source-close":
					f.InternalSource.InternalFinish = func() error { return errors.New("close failure") }
				}
				return a
			}
			r, err := f.InternalRun()
			if err == nil || r.State != admodel.ObjectSyncAccepted || f.InternalWrites != 1 {
				t.Fatalf("%+v %v", r, err)
			}
			if name != "source-close" &&
				(r.Verified || !errors.Is(err, admodel.ErrObjectSyncReadback)) {
				t.Fatalf("%+v %v", r, err)
			}
		})
	}
}

func (f *InternalSyncFixture) InternalPassword() {
	f.InternalRequest.PasswordOnly = true
	f.InternalRequest.Properties = nil
	f.InternalDst[InternalSyncTestTarget]["msds-isrodc"] = [][]byte{[]byte("TRUE")}
	f.InternalDst[InternalSyncTestTarget]["msds-hasfullreplicancs"] = [][]byte{
		[]byte(InternalSyncTestNC),
		[]byte(InternalSyncTestConfig),
	}
	server, _ := admodel.InternalParentDirectoryDN(InternalSyncTestTarget)
	computer := "CN=RODC," + InternalSyncTestNC
	f.InternalDst[server] = map[string][][]byte{"serverreference": {[]byte(computer)}}
	f.InternalDst[computer] = map[string][][]byte{
		"msds-revealedlist": {[]byte("S:10:unicodePwd:" + InternalSyncTestObject)},
	}
}

func TestSyncObjectPasswordOnly(t *testing.T) {
	for _, name := range []string{"allowed", "denied", "no-policy", "missing-policy", "permission", "no-control", "no-marker"} {
		t.Run(name, func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			f.InternalPassword()
			switch name {
			case "denied", "no-policy", "missing-policy":
				f.InternalTarget.InternalPolicy = func(context.Context, string, string) (map[string][][]byte, error) {
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
				f.InternalTarget.InternalPolicy = func(context.Context, string, string) (map[string][][]byte, error) {
					return nil, &admodel.LDAPError{Code: 50}
				}
			case "no-control":
				delete(f.InternalDst[""], "supportedcontrol")
			case "no-marker":
				delete(f.InternalDst["CN=RODC,"+InternalSyncTestNC], "msds-revealedlist")
			}
			r, err := f.InternalRun()
			if name == "allowed" {
				if err != nil || !r.Verified || !r.SecretCacheObserved || f.InternalWrites != 1 ||
					f.InternalPolicyCalls != 1 {
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
			if f.InternalWrites != wantWrites {
				t.Fatal(f.InternalWrites)
			}
		})
	}
}

func TestSyncObjectPortableValidationAndUnreachableSource(t *testing.T) {
	f := InternalNewSyncFixture(t)
	for _, change := range []func(*admodel.SyncObjectRequest){
		func(r *admodel.SyncObjectRequest) { r.Source.Endpoint.Host = "" }, func(r *admodel.SyncObjectRequest) { r.Partition = "" }, func(r *admodel.SyncObjectRequest) { r.Object = admodel.SyncObjectIdentity{} }, func(r *admodel.SyncObjectRequest) { r.Object.ObjectGUID = make([]byte, 16) }, func(r *admodel.SyncObjectRequest) { r.Object = admodel.SyncObjectIdentity{ObjectGUID: []byte{1}} }, func(r *admodel.SyncObjectRequest) { r.Properties = []string{"*"} }, func(r *admodel.SyncObjectRequest) { r.Properties = []string{"member;range=0-*"} }, func(r *admodel.SyncObjectRequest) { r.PasswordOnly = true },
	} {
		r := f.InternalRequest
		change(&r)
		if r.Validate() == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	c := adengine.InternalNewClient(admodel.Config{Timeout: time.Second}, f.InternalTarget)
	defer c.Close()
	unreachable := &admodel.LDAPError{Code: 81}
	r, err := adengine.InternalClientSyncObjectDial(c,
		context.Background(),
		f.InternalRequest,
		func(context.Context, admodel.Config) (*adengine.Client, error) { return nil, unreachable },
	)
	if !errors.Is(err, unreachable) || f.InternalWrites != 0 ||
		r.State != admodel.ObjectSyncNotAttempted {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestSyncObjectPasswordMarkerIgnoresUnrelatedPrincipals(t *testing.T) {
	for _, code := range []uint32{32, 50} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			f.InternalPassword()
			const unrelated = "CN=Unrelated," + InternalSyncTestNC
			f.InternalDst["CN=RODC,"+InternalSyncTestNC]["msds-revealedlist"] = [][]byte{
				[]byte("S:10:unicodePwd:" + unrelated),
				[]byte("S:10:unicodePwd:" + strings.ToUpper(InternalSyncTestObject)),
			}
			read := f.InternalTarget.InternalBase
			unrelatedReads, matchingReads := 0, 0
			f.InternalTarget.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
				if dn == unrelated {
					unrelatedReads++
					return nil, &admodel.LDAPError{Operation: "unrelated account", Code: code}
				}
				if dn == strings.ToUpper(InternalSyncTestObject) {
					matchingReads++
					return read(ctx, InternalSyncTestObject, properties)
				}
				return read(ctx, dn, properties)
			}
			result, err := f.InternalRun()
			if err != nil || result.State != admodel.ObjectSyncAccepted || !result.Verified ||
				!result.SecretCacheObserved ||
				f.InternalWrites != 1 ||
				unrelatedReads != 0 ||
				matchingReads != 1 {
				t.Fatalf(
					"%+v %v writes=%d unrelated=%d matching=%d",
					result,
					err,
					f.InternalWrites,
					unrelatedReads,
					matchingReads,
				)
			}
		})
	}
}

func TestSyncObjectPasswordMarkerRequiresMatchingGUID(t *testing.T) {
	for _, name := range []string{"different-guid", "matching-unreadable", "renamed-marker"} {
		t.Run(name, func(t *testing.T) {
			f := InternalNewSyncFixture(t)
			f.InternalPassword()
			read := f.InternalTarget.InternalBase
			markerReads := 0
			if name == "renamed-marker" {
				f.InternalDst["CN=RODC,"+InternalSyncTestNC]["msds-revealedlist"] = [][]byte{
					[]byte("S:10:unicodePwd:CN=Renamed,OU=Objects," + InternalSyncTestNC),
				}
			}
			f.InternalTarget.InternalBase = func(ctx context.Context, dn string, properties []string) (map[string][][]byte, error) {
				if dn == InternalSyncTestObject {
					markerReads++
					if name == "matching-unreadable" {
						return nil, &admodel.LDAPError{
							Operation: "requested cache marker",
							Code:      50,
						}
					}
					attrs, err := read(ctx, dn, properties)
					attrs = maps.Clone(attrs)
					attrs["objectguid"] = f.InternalSrc[InternalSyncTestNC]["objectguid"]
					return attrs, err
				}
				return read(ctx, dn, properties)
			}
			result, err := f.InternalRun()
			if !errors.Is(err, admodel.ErrObjectSyncReadback) ||
				result.State != admodel.ObjectSyncAccepted ||
				result.Verified ||
				result.SecretCacheObserved ||
				f.InternalWrites != 1 {
				t.Fatalf("%+v %v writes=%d", result, err, f.InternalWrites)
			}
			wantReads := 1
			if name == "renamed-marker" {
				wantReads = 0
			}
			if markerReads != wantReads {
				t.Fatalf("marker reads=%d want=%d", markerReads, wantReads)
			}
			if name == "matching-unreadable" && !errors.Is(err, admodel.ErrObjectSyncPermission) {
				t.Fatal("matching marker permission failure lost", err)
			}
		})
	}
}
