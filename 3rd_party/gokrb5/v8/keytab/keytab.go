// Package keytab implements Kerberos keytabs: https://web.mit.edu/kerberos/krb5-devel/doc/formats/keytab_file_format.html.
package keytab

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/crypto"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

const (
	keytabFirstByte byte = 0o5
)

// Keytab struct.
type Keytab struct {
	version uint8
	Entries []entry `json:"Entries"`
}

// Keytab entry struct.
type entry struct {
	Principal principal           `json:"Principal"`
	Timestamp time.Time           `json:"Timestamp"`
	KVNO8     uint8               `json:"KVNO8"`
	Key       types.EncryptionKey `json:"Key"`
	KVNO      uint32              `json:"KVNO"`
}

func (e entry) String() string {
	return fmt.Sprintf("% 4d %s %-56s %2d %-64x",
		e.KVNO8,
		e.Timestamp.Format("02/01/06 15:04:05"),
		e.Principal.String(),
		e.Key.KeyType,
		e.Key.KeyValue,
	)
}

// Keytab entry principal struct.
type principal struct {
	NumComponents int16    `json:"-"`
	Realm         string   `json:"Realm"`
	Components    []string `json:"Components"`
	NameType      int32    `json:"NameType"`
}

func (p principal) String() string {
	return fmt.Sprintf("%s@%s", strings.Join(p.Components, "/"), p.Realm)
}

// New creates new, empty Keytab type.
func New() *Keytab {
	var e []entry
	return &Keytab{
		version: 2,
		Entries: e,
	}
}

// GetEncryptionKey returns the EncryptionKey from the Keytab for the newest entry with the required kvno, etype and matching principal.
// If the kvno is zero then the latest kvno will be returned. The kvno is also returned for
func (kt *Keytab) GetEncryptionKey(princName types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, int, error) {
	var key types.EncryptionKey
	if kvno < 0 || uint64(kvno) > math.MaxUint32 {
		return key, 0, errors.New("invalid key version")
	}
	var t time.Time
	var kv int
	for _, k := range kt.Entries {
		if k.Principal.Realm == realm && len(k.Principal.Components) == len(princName.NameString) &&
			k.Key.KeyType == etype &&
			(k.KVNO == uint32(kvno) || kvno == 0) &&
			k.Timestamp.After(t) {
			p := true
			for i, n := range k.Principal.Components {
				if princName.NameString[i] != n {
					p = false
					break
				}
			}
			if p {
				key = k.Key
				kv = int(k.KVNO)
				t = k.Timestamp
			}
		}
	}
	if len(key.KeyValue) < 1 {
		return key, 0, fmt.Errorf("matching key not found in keytab. Looking for %q realm: %v kvno: %v etype: %v", princName.PrincipalNameString(), realm, kvno, etype)
	}
	return key, kv, nil
}

// Create a new Keytab entry.
func newEntry() entry {
	var b []byte
	return entry{
		Principal: newPrincipal(),
		Timestamp: time.Time{},
		KVNO8:     0,
		Key: types.EncryptionKey{
			KeyType:  0,
			KeyValue: b,
		},
		KVNO: 0,
	}
}

func (kt Keytab) String() string {
	var s string
	s = "KVNO Timestamp         Principal                                                ET Key\n---- -----" +
		"------------ -------------------------------------------------------- -- -------------------------" +
		"---------------------------------------\n"
	for _, entry := range kt.Entries {
		s += entry.String() + "\n"
	}
	return s
}

// AddEntry adds an entry to the keytab. The password should be provided in plain text and it will be converted using the defined enctype to be stored.
func (kt *Keytab) AddEntry(principalName, realm, password string, ts time.Time, KVNO uint8, encType int32) error {
	// Generate a key from the password
	princ, _ := types.ParseSPNString(principalName)
	key, _, err := crypto.GetKeyFromPassword(password, princ, realm, encType, types.PADataSequence{})
	if err != nil {
		return err
	}

	// Populate the keytab entry principal
	ktep := newPrincipal()
	componentCount := len(princ.NameString)
	if componentCount < 0 || componentCount > math.MaxInt16-1 {
		return errors.New("too many principal components")
	}
	ktep.NumComponents = int16(componentCount)
	if kt.version == 1 {
		ktep.NumComponents += 1
	}

	ktep.Realm = realm
	ktep.Components = princ.NameString
	ktep.NameType = princ.NameType

	// Populate the keytab entry
	e := newEntry()
	e.Principal = ktep
	e.Timestamp = ts
	e.KVNO8 = KVNO
	e.KVNO = uint32(KVNO)
	e.Key = key

	kt.Entries = append(kt.Entries, e)
	return nil
}

// Create a new principal.
func newPrincipal() principal {
	var c []string
	return principal{
		NumComponents: 0,
		Realm:         "",
		Components:    c,
		NameType:      0,
	}
}

// Load a Keytab file into a Keytab type.
func Load(ktPath string) (*Keytab, error) {
	kt := new(Keytab)
	b, err := os.ReadFile(ktPath)
	if err != nil {
		return kt, err
	}
	err = kt.Unmarshal(b)
	return kt, err
}

// Marshal keytab into byte slice
func (kt *Keytab) Marshal() ([]byte, error) {
	b := []byte{keytabFirstByte, kt.version}
	for _, e := range kt.Entries {
		eb, err := e.marshal(int(kt.version))
		if err != nil {
			return b, err
		}
		b = append(b, eb...)
	}
	return b, nil
}

// Write the keytab bytes to io.Writer.
// Returns the number of bytes written
func (kt *Keytab) Write(w io.Writer) (int, error) {
	b, err := kt.Marshal()
	if err != nil {
		return 0, fmt.Errorf("error marshaling keytab: %w", err)
	}
	return w.Write(b)
}

// Unmarshal byte slice of Keytab data into Keytab type.
func (kt *Keytab) Unmarshal(b []byte) error {
	if len(b) < 2 {
		return fmt.Errorf("byte array is less than 2 bytes: %d", len(b))
	}

	// The first byte of the file always has the value 5
	if b[0] != keytabFirstByte {
		return errors.New("invalid keytab data. First byte does not equal 5")
	}
	// Get keytab version
	// The 2nd byte contains the version number (1 or 2)
	kt.version = b[1]
	if kt.version != 1 && kt.version != 2 {
		return errors.New("invalid keytab data. Keytab version is neither 1 nor 2")
	}
	// Version 1 of the file format uses native byte order for integer representations. Version 2 always uses big-endian byte order
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if kt.version == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	// n tracks position in the byte array
	n := 2
	l, err := readInt32(b, &n, &endian)
	if err != nil {
		return err
	}
	for l != 0 {
		if l < 0 {
			// Zero padded so skip over
			skip := -int64(l)
			if skip > int64(len(b)-n) {
				return io.ErrUnexpectedEOF
			}
			n += int(skip)
		} else {
			if n < 0 {
				return fmt.Errorf("%d can't be less than zero", n)
			}
			if n+int(l) > len(b) {
				return fmt.Errorf("%s's length is less than %d", b, n+int(l))
			}
			eb := b[n : n+int(l)]
			n = n + int(l)
			ke := newEntry()
			// p keeps track as to where we are in the byte stream
			var p int
			var err error
			if err := parsePrincipal(eb, &p, kt, &ke, &endian); err != nil {
				return err
			}
			ke.Timestamp, err = readTimestamp(eb, &p, &endian)
			if err != nil {
				return err
			}
			rei8, err := readInt8(eb, &p, &endian)
			if err != nil {
				return err
			}
			ke.KVNO8 = byte(int(rei8) & 0xff)
			rei16, err := readInt16(eb, &p, &endian)
			if err != nil {
				return err
			}
			ke.Key.KeyType = int32(rei16)
			rei16, err = readInt16(eb, &p, &endian)
			if err != nil {
				return err
			}
			kl := int(rei16)
			ke.Key.KeyValue, err = readBytes(eb, &p, kl, &endian)
			if err != nil {
				return err
			}
			// The 32-bit key version overrides the 8-bit key version.
			// If at least 4 bytes are left after the other fields are read and they are non-zero
			// this indicates the 32-bit version is present.
			if len(eb)-p >= 4 {
				// The 32-bit key may be present
				ri32, err := readUint32(eb, &p, &endian)
				if err != nil {
					return err
				}
				ke.KVNO = ri32
			}
			if ke.KVNO == 0 {
				// Handles if the value from the last 4 bytes was zero and also if there are not the 4 bytes present. Makes sense to put the same value here as KVNO8
				ke.KVNO = uint32(ke.KVNO8)
			}
			// Add the entry to the keytab
			kt.Entries = append(kt.Entries, ke)
		}
		// Check if there are still 4 bytes left to read
		// Also check that n is greater than zero
		if n < 0 || n > len(b) || len(b[n:]) < 4 {
			break
		}
		// Read the size of the next entry
		l, err = readInt32(b, &n, &endian)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e entry) marshal(v int) ([]byte, error) {
	var b []byte
	pb, err := e.Principal.marshal(v)
	if err != nil {
		return b, err
	}
	b = append(b, pb...)

	var endian binary.ByteOrder
	endian = binary.BigEndian
	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}

	keyLength := len(e.Key.KeyValue)
	stamp := e.Timestamp.Unix()
	if stamp < 0 || stamp > math.MaxUint32 || e.Key.KeyType < 0 || e.Key.KeyType > math.MaxUint16 || keyLength < 0 || keyLength > math.MaxUint16 {
		return nil, errors.New("keytab entry exceeds wire field bounds")
	}
	t := make([]byte, 9)
	endian.PutUint32(t[0:4], uint32(stamp))
	t[4] = e.KVNO8
	endian.PutUint16(t[5:7], uint16(e.Key.KeyType))
	endian.PutUint16(t[7:9], uint16(keyLength))
	b = append(b, t...)

	buf := new(bytes.Buffer)
	err = binary.Write(buf, endian, e.Key.KeyValue)
	if err != nil {
		return b, err
	}
	b = append(b, buf.Bytes()...)

	t = make([]byte, 4)
	endian.PutUint32(t, e.KVNO)
	b = append(b, t...)

	// Add the length header
	t = make([]byte, 4)
	entryLength := len(b)
	if entryLength < 0 || entryLength > math.MaxInt32 {
		return nil, errors.New("keytab entry too large")
	}
	endian.PutUint32(t, uint32(entryLength))
	b = append(t, b...)
	return b, nil
}

// Parse the Keytab bytes of a principal into a Keytab entry's principal.
func parsePrincipal(b []byte, p *int, kt *Keytab, ke *entry, e *binary.ByteOrder) error {
	var err error
	ke.Principal.NumComponents, err = readInt16(b, p, e)
	if err != nil {
		return err
	}
	if ke.Principal.NumComponents < 0 {
		return errors.New("invalid principal component count")
	}
	if kt.version == 1 {
		// In version 1 the number of components includes the realm. Minus 1 to make consistent with version 2
		if ke.Principal.NumComponents == 0 {
			return errors.New("invalid version-one principal component count")
		}
		ke.Principal.NumComponents--
	}
	lenRealm, err := readInt16(b, p, e)
	if err != nil {
		return err
	}
	realmB, err := readBytes(b, p, int(lenRealm), e)
	if err != nil {
		return err
	}
	ke.Principal.Realm = string(realmB)
	for i := 0; i < int(ke.Principal.NumComponents); i++ {
		l, err := readInt16(b, p, e)
		if err != nil {
			return err
		}
		compB, err := readBytes(b, p, int(l), e)
		if err != nil {
			return err
		}
		ke.Principal.Components = append(ke.Principal.Components, string(compB))
	}
	if kt.version != 1 {
		// Name Type is omitted in version 1
		ke.Principal.NameType, err = readInt32(b, p, e)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p principal) marshal(v int) ([]byte, error) {
	//var b []byte
	b := make([]byte, 2)
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	if p.NumComponents < 0 {
		return nil, errors.New("invalid principal component count")
	}
	endian.PutUint16(b[0:], uint16(p.NumComponents))
	realm, err := marshalString(p.Realm, v)
	if err != nil {
		return b, err
	}
	b = append(b, realm...)
	for _, c := range p.Components {
		cb, err := marshalString(c, v)
		if err != nil {
			return b, err
		}
		b = append(b, cb...)
	}
	if v != 1 {
		t := make([]byte, 4)
		var nameType bytes.Buffer
		if err := binary.Write(&nameType, endian, p.NameType); err != nil {
			return nil, err
		}
		copy(t, nameType.Bytes())
		b = append(b, t...)
	}
	return b, nil
}

func marshalString(s string, v int) ([]byte, error) {
	sb := []byte(s)
	b := make([]byte, 2)
	var endian binary.ByteOrder
	endian = binary.BigEndian
	if v == 1 && isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	stringLength := len(sb)
	if stringLength < 0 || stringLength > math.MaxUint16 {
		return nil, errors.New("keytab string too large")
	}
	endian.PutUint16(b[0:], uint16(stringLength))
	buf := new(bytes.Buffer)
	err := binary.Write(buf, endian, sb)
	if err != nil {
		return b, err
	}
	b = append(b, buf.Bytes()...)
	return b, err
}

// Read bytes representing a timestamp.
func readTimestamp(b []byte, p *int, e *binary.ByteOrder) (time.Time, error) {
	i32, err := readUint32(b, p, e)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(i32), 0), nil
}

// Read bytes representing an eight bit integer.
func readInt8(b []byte, p *int, e *binary.ByteOrder) (i int8, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 1) > len(b) {
		return 0, fmt.Errorf("%s's length is less than %d", b, *p+1)
	}
	buf := bytes.NewBuffer(b[*p : *p+1])
	if err = binary.Read(buf, *e, &i); err != nil {
		return
	}
	*p++
	return
}

// Read bytes representing a sixteen bit integer.
func readInt16(b []byte, p *int, e *binary.ByteOrder) (i int16, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 2) > len(b) {
		return 0, fmt.Errorf("%s's length is less than %d", b, *p+2)
	}

	buf := bytes.NewBuffer(b[*p : *p+2])
	if err = binary.Read(buf, *e, &i); err != nil {
		return
	}
	*p += 2
	return
}

// Read bytes representing a thirty two bit integer.
func readInt32(b []byte, p *int, e *binary.ByteOrder) (i int32, err error) {
	if *p < 0 {
		return 0, fmt.Errorf("%d cannot be less than zero", *p)
	}

	if (*p + 4) > len(b) {
		return 0, fmt.Errorf("%s's length is less than %d", b, *p+4)
	}

	buf := bytes.NewBuffer(b[*p : *p+4])
	if err = binary.Read(buf, *e, &i); err != nil {
		return
	}
	*p += 4
	return
}

func readBytes(b []byte, p *int, s int, e *binary.ByteOrder) ([]byte, error) {
	if *p < 0 || *p > len(b) || s < 0 || s > len(b)-*p {
		return nil, io.ErrUnexpectedEOF
	}
	out := append([]byte(nil), b[*p:*p+s]...)
	*p += s
	return out, nil
}

func readUint32(b []byte, p *int, e *binary.ByteOrder) (uint32, error) {
	data, err := readBytes(b, p, 4, e)
	if err != nil {
		return 0, err
	}
	return (*e).Uint32(data), nil
}

func isNativeEndianLittle() bool {
	x := 0x012345678
	p := unsafe.Pointer(&x)
	bp := (*[4]byte)(p)

	var endian bool
	if 0x01 == bp[0] {
		endian = false
	} else if (0x78 & 0xff) == (bp[0] & 0xff) {
		endian = true
	} else {
		// Default to big endian
		endian = false
	}
	return endian
}

// JSON return information about the keys held in the keytab in a JSON format.
func (kt *Keytab) JSON() (string, error) {
	b, err := json.MarshalIndent(kt, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
