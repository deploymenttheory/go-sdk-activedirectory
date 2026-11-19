package acceptance

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/errorcode"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/flags"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/keyusage"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/msgtype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/iana/patype"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

const (
	portableKerberosRealm    = "AD.SDK.TEST"
	portableKerberosUser     = "owned-kerberos-fixture"
	portableKerberosPassword = "unit-fixture-only-credential"
)

// This fixture implements actual TCP AS/TGS exchanges, including encrypted
// password preauthentication. It never replaces the LDAP bind or GSS mechanism.
type portableKerberosKDC struct {
	listener         net.Listener
	keys             *keytab.Keytab
	clientKey        types.EncryptionKey
	done             chan error
	requests         atomic.Int32
	refuseAS         int32
	refuseTGS        int32
	stallAS          bool
	started          chan struct{}
	delegation       bool
	inspectAP        func(*messages.APReq) error
	mutateIssuedPart func(messages.KDCReqFields, *messages.EncKDCRepPart)
	ticketEnd        func(messages.KDCReqFields, time.Time) time.Time
}

func newPortableKerberosKDC(t *testing.T, options ...func(*portableKerberosKDC)) *portableKerberosKDC {
	t.Helper()
	keys := keytab.New()
	for _, service := range []string{"krbtgt/" + portableKerberosRealm, "ldap/" + portableTLSHost} {
		if err := keys.AddEntry(service, portableKerberosRealm, "owned-service-fixture-key", time.Now().Add(-time.Hour), 1, 18); err != nil {
			t.Fatal(err)
		}
	}
	clientKey, _, err := crypto.GetKeyFromPassword(portableKerberosPassword, types.NewPrincipalName(1, portableKerberosUser), portableKerberosRealm, 18, nil)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	kdc := &portableKerberosKDC{listener: listener, keys: keys, clientKey: clientKey, done: make(chan error, 1), started: make(chan struct{})}
	for _, option := range options {
		option(kdc)
	}
	go func() { kdc.done <- kdc.serve(t.Context()) }()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-kdc.done:
			if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				t.Error(err)
			}
		case <-time.After(6 * time.Second):
			t.Error("owned KDC fixture did not retire")
		}
		clear(clientKey.KeyValue)
		for i := range keys.Entries {
			clear(keys.Entries[i].Key.KeyValue)
		}
	})
	return kdc
}

func (k *portableKerberosKDC) serve(ctx context.Context) error {
	for {
		conn, err := k.listener.Accept()
		if err != nil {
			return err
		}
		err = k.exchange(ctx, conn)
		_ = conn.Close()
		if err != nil {
			return err
		}
	}
}

func (k *portableKerberosKDC) exchange(ctx context.Context, conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 65536 {
		return errors.New("owned KDC request outside fixture bound")
	}
	request := make([]byte, size)
	if _, err := io.ReadFull(conn, request); err != nil {
		return err
	}
	k.requests.Add(1)
	var response []byte
	var err error
	switch request[0] {
	case 0x6a:
		if k.stallAS {
			close(k.started)
			_, err = io.Copy(io.Discard, conn)
			return err
		}
		var as messages.ASReq
		if err = as.Unmarshal(request); err != nil {
			return err
		}
		response, err = k.asReply(as)
	case 0x6c:
		var tgs messages.TGSReq
		if err = tgs.Unmarshal(request); err != nil {
			return err
		}
		response, err = k.tgsReply(tgs)
	default:
		return errors.New("owned KDC received a foreign authentication protocol")
	}
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(response)))
	_, err = conn.Write(append(header[:], response...))
	return err
}

func (k *portableKerberosKDC) asReply(request messages.ASReq) ([]byte, error) {
	if request.ReqBody.Realm != portableKerberosRealm || request.ReqBody.CName.PrincipalNameString() != portableKerberosUser {
		return nil, errors.New("owned AS request changed explicit identity")
	}
	if k.delegation && !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwardable) {
		return nil, errors.New("explicit delegation omitted the forwardable AS request")
	}
	if k.refuseAS != 0 {
		return k.refusal(request.ReqBody.SName, request.ReqBody.CName, k.refuseAS)
	}
	preauthenticated := false
	for _, pa := range request.PAData {
		if pa.PADataType != patype.PA_ENC_TIMESTAMP {
			continue
		}
		var encrypted types.EncryptedData
		if err := encrypted.Unmarshal(pa.PADataValue); err != nil {
			return nil, err
		}
		plain, err := crypto.DecryptEncPart(encrypted, k.clientKey, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
		if err != nil {
			return k.refusal(request.ReqBody.SName, request.ReqBody.CName, errorcode.KDC_ERR_PREAUTH_FAILED)
		}
		var stamp types.PAEncTSEnc
		if _, err := asn1.Unmarshal(plain, &stamp); err != nil {
			return nil, err
		}
		clear(plain)
		if time.Since(stamp.PATimestamp) > time.Minute || stamp.PATimestamp.Sub(time.Now()) > time.Minute {
			return nil, errors.New("owned AS preauthentication timestamp is invalid")
		}
		preauthenticated = true
	}
	if !preauthenticated {
		info, err := asn1.Marshal(types.ETypeInfo2{{EType: 18, Salt: portableKerberosRealm + portableKerberosUser}})
		if err != nil {
			return nil, err
		}
		data, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}})
		if err != nil {
			return nil, err
		}
		reply := messages.NewKRBError(request.ReqBody.SName, portableKerberosRealm, errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
		reply.CName = request.ReqBody.CName
		reply.CRealm = portableKerberosRealm
		reply.EData = data
		return reply.Marshal()
	}
	fields, err := k.replyFields(request.KDCReqFields, k.clientKey, keyusage.AS_REP_ENCPART)
	if err != nil {
		return nil, err
	}
	fields.MsgType = msgtype.KRB_AS_REP
	reply := messages.ASRep{KDCRepFields: fields}
	return reply.Marshal()
}

func (k *portableKerberosKDC) tgsReply(request messages.TGSReq) ([]byte, error) {
	forwarding := k.delegation && request.ReqBody.SName.PrincipalNameString() == "krbtgt/"+portableKerberosRealm &&
		types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) && types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwardable)
	if request.ReqBody.Realm != portableKerberosRealm || request.ReqBody.SName.PrincipalNameString() != "ldap/"+portableTLSHost && !forwarding {
		return nil, errors.New("owned TGS request changed explicit realm or SPN")
	}
	var ap messages.APReq
	found := false
	for _, pa := range request.PAData {
		if pa.PADataType == patype.PA_TGS_REQ {
			if err := ap.Unmarshal(pa.PADataValue); err != nil {
				return nil, err
			}
			found = true
		}
	}
	if !found {
		return nil, errors.New("owned TGS request omitted its authenticated TGT")
	}
	if ok, err := ap.Verify(k.keys, 5*time.Minute, types.HostAddress{}, nil); err != nil || !ok {
		return nil, fmt.Errorf("owned TGS authenticator failed: %w", err)
	}
	body, err := request.ReqBody.Marshal()
	if err != nil {
		return nil, err
	}
	etype, err := crypto.GetEtype(ap.Ticket.DecryptedEncPart.Key.KeyType)
	if err != nil {
		return nil, err
	}
	if !etype.VerifyChecksum(ap.Ticket.DecryptedEncPart.Key.KeyValue, body, ap.Authenticator.Cksum.Checksum,
		keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
		return nil, errors.New("owned TGS request body did not match its authenticated checksum")
	}
	if forwarding && !types.IsFlagSet(&ap.Ticket.DecryptedEncPart.Flags, flags.Forwardable) {
		return k.refusal(request.ReqBody.SName, ap.Authenticator.CName, errorcode.KDC_ERR_BADOPTION)
	}
	request.ReqBody.CName = ap.Authenticator.CName
	if request.ReqBody.Till.After(ap.Ticket.DecryptedEncPart.EndTime) {
		request.ReqBody.Till = ap.Ticket.DecryptedEncPart.EndTime
	}
	if k.refuseTGS != 0 {
		return k.refusal(request.ReqBody.SName, request.ReqBody.CName, k.refuseTGS)
	}
	fields, err := k.replyFields(request.KDCReqFields, ap.Ticket.DecryptedEncPart.Key, keyusage.TGS_REP_ENCPART_SESSION_KEY)
	if err != nil {
		return nil, err
	}
	fields.MsgType = msgtype.KRB_TGS_REP
	reply := messages.TGSRep{KDCRepFields: fields}
	return reply.Marshal()
}

func (k *portableKerberosKDC) refusal(service, client types.PrincipalName, code int32) ([]byte, error) {
	reply := messages.NewKRBError(service, portableKerberosRealm, code, "")
	reply.CName, reply.CRealm = client, portableKerberosRealm
	if code == errorcode.KDC_ERR_WRONG_REALM {
		reply.CRealm = "OTHER.TEST"
	}
	return reply.Marshal()
}

func (k *portableKerberosKDC) replyFields(request messages.KDCReqFields, replyKey types.EncryptionKey, usage uint32) (messages.KDCRepFields, error) {
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(time.Hour)
	if !request.ReqBody.Till.IsZero() && request.ReqBody.Till.Before(end) {
		end = request.ReqBody.Till
	}
	if k.ticketEnd != nil {
		end = k.ticketEnd(request, end)
	}
	ticketFlags := types.NewKrbFlags()
	if k.delegation {
		types.SetFlag(&ticketFlags, flags.Forwardable)
		if request.ReqBody.SName.PrincipalNameString() == "ldap/"+portableTLSHost {
			types.SetFlag(&ticketFlags, flags.OKAsDelegate)
		}
		if types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) {
			types.SetFlag(&ticketFlags, flags.Forwarded)
		}
	}
	ticket, key, err := messages.NewTicket(request.ReqBody.CName, portableKerberosRealm, request.ReqBody.SName, portableKerberosRealm, ticketFlags, k.keys, 18, 1,
		now, now, end, time.Time{})
	if err != nil {
		return messages.KDCRepFields{}, err
	}
	defer clear(key.KeyValue)
	part := messages.EncKDCRepPart{
		Key: key, Nonce: request.ReqBody.Nonce, Flags: ticketFlags, AuthTime: now, StartTime: now, EndTime: end,
		SRealm: portableKerberosRealm, SName: request.ReqBody.SName,
	}
	if k.mutateIssuedPart != nil {
		k.mutateIssuedPart(request, &part)
	}
	plain, err := part.Marshal()
	if err != nil {
		return messages.KDCRepFields{}, err
	}
	defer clear(plain)
	encrypted, err := crypto.GetEncryptedData(plain, replyKey, usage, 0)
	if err != nil {
		return messages.KDCRepFields{}, err
	}
	return messages.KDCRepFields{PVNO: 5, CName: request.ReqBody.CName, CRealm: portableKerberosRealm, Ticket: ticket, EncPart: encrypted}, nil
}

type portableKerberosDialer struct {
	ldap *portableLDAPWire
	kdc  *portableKerberosKDC
}

func (d portableKerberosDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == net.JoinHostPort(portableTLSHost, "88") && network == "tcp" {
		return (&net.Dialer{}).DialContext(ctx, network, d.kdc.listener.Addr().String())
	}
	return d.ldap.DialContext(ctx, network, address)
}
