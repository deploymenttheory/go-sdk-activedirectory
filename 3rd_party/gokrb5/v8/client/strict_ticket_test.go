package client_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/config"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/msgtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

func TestStrictTGSExchangeBindsRequestedPrincipalAndLifetime(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*messages.TGSRep)
	}{
		{name: "valid"},
		{name: "foreign ticket service", mutate: func(r *messages.TGSRep) { r.Ticket.SName.NameString = []string{"ldap", "other.example.test"} }},
		{name: "foreign encrypted service", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.SName.NameString = []string{"ldap", "other.example.test"} }},
		{name: "foreign client realm", mutate: func(r *messages.TGSRep) { r.CRealm = "OTHER.TEST" }},
		{name: "expired", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.EndTime = time.Now().Add(-time.Minute) }},
		{name: "not yet valid", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.StartTime = time.Now().Add(time.Hour) }},
		{name: "invalid flag", mutate: func(r *messages.TGSRep) { types.SetFlag(&r.DecryptedEncPart.Flags, flags.Invalid) }},
		{name: "weak session key", mutate: func(r *messages.TGSRep) {
			r.DecryptedEncPart.Key = types.EncryptionKey{KeyType: 23, KeyValue: make([]byte, 16)}
		}},
		{name: "truncated session key", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.Key.KeyValue = []byte{1} }},
		{name: "foreign nonce", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.Nonce++ }},
		{name: "trailing envelope", mutate: func(*messages.TGSRep) {}},
		{name: "unrequested AES profile", mutate: func(r *messages.TGSRep) { r.DecryptedEncPart.Key.KeyType = 20 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			cname := types.NewPrincipalName(1, "owned-fixture")
			spn := types.NewPrincipalName(2, "ldap/dc.example.test")
			key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{0x31}, 32)}
			request := messages.TGSReq{KDCReqFields: messages.KDCReqFields{
				PVNO: 5, MsgType: msgtype.KRB_TGS_REQ,
				ReqBody: messages.KDCReqBody{
					KDCOptions: types.NewKrbFlags(), CName: cname, Realm: "EXAMPLE.TEST", SName: spn,
					Till: now.Add(time.Hour), Nonce: 42, EType: []int32{18, 17},
				},
			}}
			reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
				PVNO: 5, MsgType: msgtype.KRB_TGS_REP, CRealm: "EXAMPLE.TEST", CName: cname,
				Ticket: messages.Ticket{TktVNO: 5, Realm: "EXAMPLE.TEST", SName: spn, EncPart: types.EncryptedData{EType: 18, Cipher: []byte{1}}},
				DecryptedEncPart: messages.EncKDCRepPart{
					Key: key, Nonce: 42, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour),
					SRealm: "EXAMPLE.TEST", SName: spn,
				},
			}}
			if test.mutate != nil {
				test.mutate(&reply)
			}
			plain, err := reply.DecryptedEncPart.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			reply.EncPart, err = crypto.GetEncryptedData(plain, key, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := reply.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "trailing envelope" {
				wire = append(wire, 0)
			}
			endpoint, done := strictTicketKDC(t, wire)
			cfg := config.New()
			cfg.LibDefaults.UDPPreferenceLimit = 1
			cfg.Realms = []config.Realm{{Realm: "EXAMPLE.TEST", KDC: []string{endpoint}}}
			cl := client.NewWithPassword("owned-fixture", "EXAMPLE.TEST", "unused", cfg, client.StrictRealm("EXAMPLE.TEST"))
			t.Cleanup(cl.Destroy)
			_, _, err = cl.TGSExchange(request, "EXAMPLE.TEST", messages.Ticket{}, key, 0)
			if (err == nil) != (test.mutate == nil) {
				t.Fatalf("TGS validation error = %v", err)
			}
			if fixtureErr := <-done; fixtureErr != nil {
				t.Fatal(fixtureErr)
			}
		})
	}
}

func strictTicketKDC(t *testing.T, response []byte) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		var header [4]byte
		if _, err = io.ReadFull(conn, header[:]); err != nil {
			done <- err
			return
		}
		if binary.BigEndian.Uint32(header[:]) > 65536 {
			done <- io.ErrUnexpectedEOF
			return
		}
		request := make([]byte, binary.BigEndian.Uint32(header[:]))
		if _, err = io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}
		var decoded messages.TGSReq
		if request[0] == 0x6a {
			var as messages.ASReq
			err = as.Unmarshal(request)
		} else {
			err = decoded.Unmarshal(request)
		}
		if err != nil {
			done <- err
			return
		}
		binary.BigEndian.PutUint32(header[:], uint32(len(response)))
		_, err = conn.Write(append(header[:], response...))
		done <- err
	}()
	return listener.Addr().String(), done
}
