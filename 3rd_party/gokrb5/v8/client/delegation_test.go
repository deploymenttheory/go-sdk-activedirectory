package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/msgtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

const delegationRealm = "EXAMPLE.TEST"

func TestDelegationFreshForwardedTGTAndServicePolicyFourAES(t *testing.T) {
	for _, profile := range []int32{17, 18, 19, 20} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			cl, complete, expectedKey := delegationWireClient(t, profile, nil)
			selected, encoded, expires, err := cl.GetServiceTicketWithDelegation("ldap/dc.example.test")
			if err != nil {
				t.Fatal(err)
			}
			defer clear(selected.Key.KeyValue)
			defer clear(encoded)
			if !expires.After(time.Now()) || selected.Ticket.SName.PrincipalNameString() != "ldap/dc.example.test" {
				t.Fatal("delegation changed actual service identity or lifetime")
			}
			var credential messages.KRBCred
			if err := credential.Unmarshal(encoded); err != nil {
				t.Fatal(err)
			}
			if err := credential.DecryptEncPart(selected.Key); err != nil {
				t.Fatal(err)
			}
			if len(credential.Tickets) != 1 || credential.Tickets[0].SName.PrincipalNameString() != "krbtgt/"+delegationRealm ||
				len(credential.DecryptedEncPart.TicketInfo) != 1 {
				t.Fatal("forwarding did not transfer exactly the selected realm TGT")
			}
			info := credential.DecryptedEncPart.TicketInfo[0]
			defer clear(info.Key.KeyValue)
			if !bytes.Equal(info.Key.KeyValue, expectedKey.KeyValue) || !types.IsFlagSet(&info.Flags, flags.Forwarded) ||
				!types.IsFlagSet(&info.Flags, flags.Forwardable) || !info.EndTime.Equal(expires) || info.PRealm != delegationRealm ||
				info.PName.PrincipalNameString() != "fixture-user" || !info.SName.Equal(credential.Tickets[0].SName) {
				t.Fatal("delegated ticket metadata/key does not match the fresh KDC reply")
			}
			if err := <-complete; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDelegationRejectsKDCPolicyIdentityAndReplyFailures(t *testing.T) {
	for _, fault := range []string{
		"service-not-trusted", "forwarded-flag-absent", "forwardable-flag-absent", "wrong-client", "wrong-realm", "wrong-service",
		"wrong-nonce", "expired", "not-yet-valid", "weak-key", "wrong-profile", "trailing", "lost-response", "kdc-refusal", "service-outlives-TGT", "forwarded-outlives-TGT",
	} {
		t.Run(fault, func(t *testing.T) {
			mutate := func(stage int, reply *messages.TGSRep) {
				if stage == 0 && fault == "service-not-trusted" {
					types.UnsetFlag(&reply.DecryptedEncPart.Flags, flags.OKAsDelegate)
				}
				if stage == 0 && fault == "service-outlives-TGT" || stage == 1 && fault == "forwarded-outlives-TGT" {
					reply.DecryptedEncPart.EndTime = time.Now().Add(2 * time.Hour)
				}
				if stage != 1 {
					return
				}
				switch fault {
				case "forwarded-flag-absent":
					types.UnsetFlag(&reply.DecryptedEncPart.Flags, flags.Forwarded)
				case "forwardable-flag-absent":
					types.UnsetFlag(&reply.DecryptedEncPart.Flags, flags.Forwardable)
				case "wrong-client":
					reply.CName = types.NewPrincipalName(1, "other-user")
				case "wrong-realm":
					reply.CRealm = "OTHER.TEST"
				case "wrong-service":
					reply.DecryptedEncPart.SName = types.NewPrincipalName(2, "krbtgt/OTHER.TEST")
				case "wrong-nonce":
					reply.DecryptedEncPart.Nonce++
				case "expired":
					reply.DecryptedEncPart.EndTime = time.Now().Add(-time.Minute)
				case "not-yet-valid":
					reply.DecryptedEncPart.StartTime = time.Now().Add(time.Hour)
				case "weak-key":
					reply.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 23, KeyValue: make([]byte, 16)}
				case "wrong-profile":
					reply.DecryptedEncPart.Key.KeyType = 20
				}
			}
			cl, complete, _ := delegationWireClient(t, 18, mutate, fault)
			selected, encoded, _, err := cl.GetServiceTicketWithDelegation("ldap/dc.example.test")
			if err == nil || len(encoded) != 0 || len(selected.Key.KeyValue) != 0 {
				t.Fatal("failed delegation returned usable credentials")
			}
			if fixtureErr := <-complete; fixtureErr != nil {
				t.Fatal(fixtureErr)
			}
		})
	}
}

func delegationWireClient(t *testing.T, profile int32, mutate func(int, *messages.TGSRep), faults ...string) (*Client, <-chan error, types.EncryptionKey) {
	t.Helper()
	size := 16
	if profile == 18 || profile == 20 {
		size = 32
	}
	initial := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x31}, size)}
	forwarded := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x43}, size)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	settings := config.New()
	settings.LibDefaults.UDPPreferenceLimit = 1
	settings.LibDefaults.NoAddresses = true
	settings.LibDefaults.DefaultTGSEnctypeIDs = []int32{profile}
	settings.Realms = []config.Realm{{Realm: delegationRealm, KDC: []string{listener.Addr().String()}}}
	cl := NewWithPassword("fixture-user", delegationRealm, "unused", settings, StrictRealm(delegationRealm), WithContext(t.Context()))
	now := time.Now().UTC().Truncate(time.Second)
	tgt := messages.Ticket{
		TktVNO: 5, Realm: delegationRealm, SName: types.NewPrincipalName(2, "krbtgt/"+delegationRealm),
		EncPart: types.EncryptedData{EType: profile, Cipher: []byte("original-opaque-TGT")},
	}
	cl.addSession(tgt, messages.EncKDCRepPart{Key: initial, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour)})
	// A cached ordinary service ticket must not substitute for fresh delegation policy.
	old := tgt
	old.SName = types.NewPrincipalName(2, "ldap/dc.example.test")
	cl.cache.addEntry(old, now, now, now.Add(time.Hour), time.Time{}, initial)
	t.Cleanup(cl.Destroy)
	complete := make(chan error, 1)
	fault := ""
	if len(faults) != 0 {
		fault = faults[0]
	}
	go func() {
		for stage := range 2 {
			if err := delegationWireReply(listener, stage, profile, initial, forwarded, mutate, fault); err != nil {
				complete <- err
				return
			}
			if stage == 0 && (fault == "service-not-trusted" || fault == "service-outlives-TGT") {
				break
			}
		}
		complete <- nil
	}()
	return cl, complete, forwarded
}

func delegationWireReply(listener net.Listener, stage int, profile int32, original, forwarded types.EncryptionKey, mutate func(int, *messages.TGSRep), fault string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > 65536 {
		return fmt.Errorf("owned delegation request exceeded fixture bound")
	}
	encoded := make([]byte, size)
	if _, err := io.ReadFull(conn, encoded); err != nil {
		return err
	}
	var request messages.TGSReq
	if err := request.Unmarshal(encoded); err != nil {
		return err
	}
	expected := "ldap/dc.example.test"
	if stage == 1 {
		expected = "krbtgt/" + delegationRealm
	}
	if request.ReqBody.SName.PrincipalNameString() != expected || request.ReqBody.Realm != delegationRealm ||
		(stage == 1 && (!types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) || !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwardable))) {
		return fmt.Errorf("owned delegation request changed explicit identity or forwarding policy")
	}
	if len(request.PAData) != 1 {
		return fmt.Errorf("owned delegation request omitted authenticated TGT")
	}
	var ap messages.APReq
	if err := ap.Unmarshal(request.PAData[0].PADataValue); err != nil {
		return err
	}
	if err := ap.DecryptAuthenticator(original); err != nil {
		return err
	}
	body, err := request.ReqBody.Marshal()
	if err != nil {
		return err
	}
	etype, err := crypto.GetEtype(profile)
	if err != nil {
		return err
	}
	if !etype.VerifyChecksum(original.KeyValue, body, ap.Authenticator.Cksum.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
		return fmt.Errorf("forwarding flags were changed after the authenticated request checksum")
	}
	if stage == 1 && fault == "lost-response" {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	resultKey := types.EncryptionKey{KeyType: profile, KeyValue: bytes.Repeat([]byte{0x42}, len(original.KeyValue))}
	resultFlags := types.NewKrbFlags()
	types.SetFlag(&resultFlags, flags.OKAsDelegate)
	if stage == 1 {
		resultKey = forwarded
		types.SetFlag(&resultFlags, flags.Forwarded)
		types.SetFlag(&resultFlags, flags.Forwardable)
	}
	reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		PVNO:    5,
		MsgType: msgtype.KRB_TGS_REP,
		CRealm:  delegationRealm,
		CName:   types.NewPrincipalName(1, "fixture-user"),
		Ticket: messages.Ticket{
			TktVNO:  5,
			Realm:   delegationRealm,
			SName:   request.ReqBody.SName,
			EncPart: types.EncryptedData{EType: profile, Cipher: []byte("fresh-opaque-ticket")},
		},
		DecryptedEncPart: messages.EncKDCRepPart{
			Key: resultKey, Flags: resultFlags, Nonce: request.ReqBody.Nonce,
			AuthTime: now, StartTime: now, EndTime: now.Add(30 * time.Minute), SRealm: delegationRealm, SName: request.ReqBody.SName,
		},
	}}
	if mutate != nil {
		mutate(stage, &reply)
	}
	plain, err := reply.DecryptedEncPart.Marshal()
	if err != nil {
		return err
	}
	defer clear(plain)
	reply.EncPart, err = crypto.GetEncryptedData(plain, original, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
	if err != nil {
		return err
	}
	wire, err := reply.Marshal()
	if stage == 1 && fault == "trailing" {
		wire = append(wire, 0)
	}
	if stage == 1 && fault == "kdc-refusal" {
		refusal := messages.NewKRBError(request.ReqBody.SName, delegationRealm, 13, "")
		wire, err = refusal.Marshal()
	}
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(wire)))
	_, err = conn.Write(append(header[:], wire...))
	return err
}
