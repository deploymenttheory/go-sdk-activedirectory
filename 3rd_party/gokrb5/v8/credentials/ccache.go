package credentials

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

const (
	headerFieldTagKDCOffset = 1
)

// CCache is the file credentials cache as define here: https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html
type CCache struct {
	Version          uint8
	Header           header
	DefaultPrincipal principal
	Credentials      []*Credential
	Path             string
}

type header struct {
	length uint16
	fields []headerField
}

type headerField struct {
	tag    uint16
	length uint16
	value  []byte
}

// Credential cache entry principal struct.
type principal struct {
	Realm         string
	PrincipalName types.PrincipalName
}

// Credential holds a Kerberos client's ccache credential information.
type Credential struct {
	Client       principal
	Server       principal
	Key          types.EncryptionKey
	AuthTime     time.Time
	StartTime    time.Time
	EndTime      time.Time
	RenewTill    time.Time
	IsSKey       bool
	TicketFlags  asn1.BitString
	Addresses    []types.HostAddress
	AuthData     []types.AuthorizationDataEntry
	Ticket       []byte
	SecondTicket []byte
}

// LoadCCache loads a credential cache file into a CCache type.
func LoadCCache(cpath string) (*CCache, error) {
	c := new(CCache)
	b, err := os.ReadFile(cpath)
	if err != nil {
		return c, err
	}
	err = c.Unmarshal(b)
	return c, err
}

// Unmarshal decodes a credential cache with input-bounded lengths and counts.
// A malformed file never installs partially parsed credentials on the receiver.
func (c *CCache) Unmarshal(b []byte) error {
	r := cacheReader{data: b, order: binary.BigEndian}
	parsed := CCache{Path: c.Path}
	if r.u8() != 5 {
		return errors.New("invalid credential cache magic")
	}
	parsed.Version = r.u8()
	if r.err != nil || parsed.Version < 1 || parsed.Version > 4 {
		return errors.New("invalid credential cache version")
	}
	if parsed.Version <= 2 {
		r.order = binary.NativeEndian
	}
	if parsed.Version == 4 {
		parsed.Header.length = r.u16()
		headerBytes := r.take(int(parsed.Header.length))
		if r.err != nil {
			return r.err
		}
		h := cacheReader{data: headerBytes, order: r.order}
		for h.pos < len(h.data) && h.err == nil {
			field := headerField{tag: h.u16(), length: h.u16()}
			field.value = h.take(int(field.length))
			if h.err != nil {
				return h.err
			}
			if !field.valid() {
				return errors.New("invalid credential cache header field")
			}
			parsed.Header.fields = append(parsed.Header.fields, field)
		}
	}
	parsed.DefaultPrincipal = r.principal(parsed.Version)
	for r.pos < len(r.data) && r.err == nil {
		cred := new(Credential)
		cred.Client = r.principal(parsed.Version)
		cred.Server = r.principal(parsed.Version)
		cred.Key.KeyType = int32(r.u16())
		if parsed.Version == 3 {
			cred.Key.KeyType = int32(r.u16())
		}
		cred.Key.KeyValue = r.counted()
		cred.AuthTime = r.timestamp()
		cred.StartTime = r.timestamp()
		cred.EndTime = r.timestamp()
		cred.RenewTill = r.timestamp()
		cred.IsSKey = r.u8() != 0
		cred.TicketFlags = types.NewKrbFlags()
		cred.TicketFlags.Bytes = r.take(4)
		n := r.count(6)
		for i := uint32(0); i < n && r.err == nil; i++ {
			cred.Addresses = append(cred.Addresses, types.HostAddress{AddrType: int32(r.u16()), Address: r.counted()})
		}
		n = r.count(6)
		for i := uint32(0); i < n && r.err == nil; i++ {
			cred.AuthData = append(cred.AuthData, types.AuthorizationDataEntry{ADType: int32(r.u16()), ADData: r.counted()})
		}
		cred.Ticket = r.counted()
		cred.SecondTicket = r.counted()
		parsed.Credentials = append(parsed.Credentials, cred)
	}
	if r.err != nil {
		return r.err
	}
	*c = parsed
	return nil
}

type cacheReader struct {
	data  []byte
	pos   int
	order binary.ByteOrder
	err   error
}

func (r *cacheReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data)-r.pos {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	out := append([]byte(nil), r.data[r.pos:r.pos+n]...)
	r.pos += n
	return out
}

func (r *cacheReader) u8() byte {
	b := r.take(1)
	if len(b) != 1 {
		return 0
	}
	return b[0]
}

func (r *cacheReader) u16() uint16 {
	b := r.take(2)
	if len(b) != 2 {
		return 0
	}
	return r.order.Uint16(b)
}

func (r *cacheReader) u32() uint32 {
	b := r.take(4)
	if len(b) != 4 {
		return 0
	}
	return r.order.Uint32(b)
}

func (r *cacheReader) counted() []byte {
	n := r.u32()
	remaining := len(r.data) - r.pos
	if remaining < 0 || uint64(n) > uint64(remaining) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	return r.take(int(n))
}

func (r *cacheReader) count(minimum int) uint32 {
	n := r.u32()
	remaining := (len(r.data) - r.pos) / minimum
	if remaining < 0 || uint64(n) > uint64(remaining) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	return n
}
func (r *cacheReader) timestamp() time.Time { return time.Unix(int64(r.u32()), 0) }
func (r *cacheReader) principal(version byte) principal {
	p := principal{}
	if version != 1 {
		u := r.u32()
		p.PrincipalName.NameType = int32(u & 0x7fffffff)
		if u&0x80000000 != 0 {
			p.PrincipalName.NameType += -2147483648
		}
	}
	n := r.count(4)
	if version == 1 {
		if n == 0 {
			r.err = errors.New("invalid version-one component count")
			return p
		}
		n--
	}
	p.Realm = string(r.counted())
	for i := uint32(0); i < n && r.err == nil; i++ {
		p.PrincipalName.NameString = append(p.PrincipalName.NameString, string(r.counted()))
	}
	return p
}

// GetClientPrincipalName returns a PrincipalName type for the client the credentials cache is for.
func (c *CCache) GetClientPrincipalName() types.PrincipalName {
	return c.DefaultPrincipal.PrincipalName
}

// GetClientRealm returns the reals of the client the credentials cache is for.
func (c *CCache) GetClientRealm() string {
	return c.DefaultPrincipal.Realm
}

// GetClientCredentials returns a Credentials object representing the client of the credentials cache.
func (c *CCache) GetClientCredentials() *Credentials {
	return &Credentials{
		username: c.DefaultPrincipal.PrincipalName.PrincipalNameString(),
		realm:    c.GetClientRealm(),
		cname:    c.DefaultPrincipal.PrincipalName,
	}
}

// Contains tests if the cache contains a credential for the provided server PrincipalName
func (c *CCache) Contains(p types.PrincipalName) bool {
	for _, cred := range c.Credentials {
		if cred.Server.PrincipalName.Equal(p) {
			return true
		}
	}
	return false
}

// GetEntry returns a specific credential for the PrincipalName provided.
func (c *CCache) GetEntry(p types.PrincipalName) (*Credential, bool) {
	cred := new(Credential)
	var found bool
	for i := range c.Credentials {
		if c.Credentials[i].Server.PrincipalName.Equal(p) {
			cred = c.Credentials[i]
			found = true
			break
		}
	}
	if !found {
		return cred, false
	}
	return cred, true
}

// GetEntries filters out configuration entries an returns a slice of credentials.
func (c *CCache) GetEntries() []*Credential {
	creds := make([]*Credential, 0)
	for _, cred := range c.Credentials {
		// Filter out configuration entries
		if strings.HasPrefix(cred.Server.Realm, "X-CACHECONF") {
			continue
		}
		creds = append(creds, cred)
	}
	return creds
}

func (h *headerField) valid() bool {
	// See https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html - Header format
	switch h.tag {
	case headerFieldTagKDCOffset:
		if h.length != 8 || len(h.value) != 8 {
			return false
		}
		return true
	}
	return false
}
