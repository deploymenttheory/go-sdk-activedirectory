package activedirectory

import (
	"errors"
	"strings"
	"testing"
)

type syncObjectReference struct {
	Schema              int    `json:"schema"`
	Revision            string `json:"revision"`
	RunID               string `json:"run_id"`
	SourceHost          string `json:"source_host"`
	SourcePort          uint16 `json:"source_port"`
	DestinationHost     string `json:"destination_host"`
	DestinationPort     uint16 `json:"destination_port"`
	Partition           string `json:"partition"`
	ObjectDN            string `json:"object_dn"`
	PasswordOnly        bool   `json:"password_only"`
	Applied             bool   `json:"applied"`
	ADModule            string `json:"ad_module"`
	SecretCacheObserved bool   `json:"secret_cache_observed"`
	Destination         struct {
		GUID       []byte              `json:"guid"`
		Attributes map[string][][]byte `json:"attributes"`
	} `json:"destination_after"`
}

var errSyncReferenceMismatch = errors.New("object-sync reference provenance or projection mismatch")

func (r syncObjectReference) validate(source, destination Endpoint, request SyncObjectRequest, revision, runID string) error {
	if r.Schema != 1 || r.Revision != revision || r.RunID != runID || !r.Applied || r.ADModule == "" || r.SourceHost != source.Host || r.SourcePort != source.Port || r.DestinationHost != destination.Host || r.DestinationPort != destination.Port || r.Partition != request.Partition || r.ObjectDN != request.Object.DistinguishedName || r.PasswordOnly != request.PasswordOnly || len(r.Destination.GUID) != 16 {
		return errSyncReferenceMismatch
	}
	if !request.PasswordOnly {
		if len(r.Destination.Attributes) != len(request.Properties) {
			return errSyncReferenceMismatch
		}
		for _, p := range request.Properties {
			if len(r.Destination.Attributes[strings.ToLower(p)]) == 0 {
				return errSyncReferenceMismatch
			}
		}
	} else if !r.SecretCacheObserved {
		return errSyncReferenceMismatch
	}
	return nil
}

func TestSyncObjectReferenceGuardsBeforeMutation(t *testing.T) {
	f := newSyncFixture(t)
	r := syncObjectReference{Schema: 1, Revision: strings.Repeat("a", 40), RunID: "fixture-1", Applied: true, ADModule: "1.0.1.0", SourceHost: f.request.Source.Endpoint.Host, SourcePort: 389, DestinationHost: "target.example.test", DestinationPort: 389, Partition: f.request.Partition, ObjectDN: f.request.Object.DistinguishedName}
	r.Destination.GUID = f.src[syncTestObject]["objectguid"][0]
	r.Destination.Attributes = map[string][][]byte{"description": {[]byte("controlled change")}}
	source := Endpoint{Host: r.SourceHost, Port: 389}
	target := Endpoint{Host: r.DestinationHost, Port: 389}
	if err := r.validate(source, target, f.request, r.Revision, r.RunID); err != nil {
		t.Fatal(err)
	}
	badProjection := r
	badProjection.Destination.Attributes = map[string][][]byte{"displayname": {[]byte("different projection")}}
	if badProjection.validate(source, target, f.request, r.Revision, r.RunID) == nil {
		t.Fatal("accepted wrong projection of the same size")
	}
	for _, mutate := range []func(*syncObjectReference){func(v *syncObjectReference) { v.Applied = false }, func(v *syncObjectReference) { v.SourceHost = target.Host }, func(v *syncObjectReference) { v.Schema = 2 }, func(v *syncObjectReference) { v.PasswordOnly = true }, func(v *syncObjectReference) { v.Revision = "other" }, func(v *syncObjectReference) { v.Destination.Attributes = nil }} {
		bad := r
		mutate(&bad)
		if bad.validate(source, target, f.request, r.Revision, r.RunID) == nil {
			t.Fatal("accepted mismatched reference")
		}
	}
}
