package activedirectory

import (
	"errors"
	"testing"
)

const outboundXML = `<DS_REPL_NEIGHBORW><pszNamingContext>DC=example,DC=test</pszNamingContext><pszSourceDsaDN>CN=NTDS Settings,CN=DC2</pszSourceDsaDN><pszSourceDsaAddress>dc2.example.test</pszSourceDsaAddress><dwReplicaFlags>2147483648</dwReplicaFlags><uuidNamingContextObjGuid>00000000-0000-0000-0000-000000000000</uuidNamingContextObjGuid><uuidSourceDsaObjGuid>00000001-0000-0000-0000-000000000000</uuidSourceDsaObjGuid><ftimeLastSyncSuccess>1601-01-01T00:00:00Z</ftimeLastSyncSuccess><ftimeLastSyncAttempt>2026-11-12T23:59:01.1234567Z</ftimeLastSyncAttempt><dwLastSyncResult>1722</dwLastSyncResult><cNumConsecutiveSyncFailures>2</cNumConsecutiveSyncFailures><futureField>future</futureField></DS_REPL_NEIGHBORW>`

func TestReplicationOutboundPreservesDirectionAndMissingFields(t *testing.T) {
	got, err := decodeOutboundPartner([]byte(outboundXML))
	if err != nil || got.Direction != ReplicationOutbound || got.PartnerDN == nil || *got.PartnerDN != "CN=NTDS Settings,CN=DC2" || got.LastResult == nil || *got.LastResult != 1722 || got.ReplicaFlags == nil || *got.ReplicaFlags != 0x80000000 {
		t.Fatalf("projection=%+v err=%v", got, err)
	}
	if got.LastSuccess.Ticks == nil || *got.LastSuccess.Ticks != 0 || got.LastSuccess.UTC != nil || got.LastAttempt.UTC == nil || got.LastAttempt.UTC.Nanosecond() != 123456700 {
		t.Fatalf("time semantics=%+v %+v", got.LastSuccess, got.LastAttempt)
	}
	if got.InvocationID != nil || got.TransportGUID != nil || got.LastObjectUSN != nil || got.AttributeFilterUSN != nil || got.TransportDN != nil {
		t.Fatal("invented inbound fields in notification metadata")
	}
	missing, err := decodeOutboundPartner([]byte(`<DS_REPL_NEIGHBORW><uuidSourceDsaObjGuid>00000001-0000-0000-0000-000000000000</uuidSourceDsaObjGuid><pszNamingContext>DC=x</pszNamingContext></DS_REPL_NEIGHBORW>`))
	if err != nil || missing.LastResult != nil || missing.LastAttempt.Ticks != nil || missing.PartnerDN != nil {
		t.Fatalf("unreported values became zero: %+v %v", missing, err)
	}
}

func TestReplicationOutboundRejectsAmbiguousXML(t *testing.T) {
	for _, raw := range []string{`<wrong/>`, `<DS_REPL_NEIGHBORW/>`, `<DS_REPL_NEIGHBORW><dwLastSyncResult>0</dwLastSyncResult><dwLastSyncResult>5</dwLastSyncResult></DS_REPL_NEIGHBORW>`, `<DS_REPL_NEIGHBORW><dwLastSyncResult>-1</dwLastSyncResult></DS_REPL_NEIGHBORW>`, `<DS_REPL_NEIGHBORW><uuidSourceDsaObjGuid>invalid</uuidSourceDsaObjGuid></DS_REPL_NEIGHBORW>`, `<DS_REPL_NEIGHBORW><ftimeLastSyncSuccess>2026-01-01T00:00:00.000000001Z</ftimeLastSyncSuccess></DS_REPL_NEIGHBORW>`, outboundXML + `<extra/>`} {
		if _, err := decodeOutboundPartner([]byte(raw)); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("accepted malformed XML: %s: %v", raw, err)
		}
	}
}
