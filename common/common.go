package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type NEXString struct {
	Length uint16
	String string
}

func (s NEXString) FromBytes(params []byte) NEXString {
	s.Length = binary.LittleEndian.Uint16(params[0:])
	s.String = string(params[2 : len(params)-1])
	return s
}

func (s NEXString) FromString(params string) NEXString {
	s.String = params
	s.Length = uint16(len(params) + 1)
	return s
}

func (s NEXString) Bytes() []byte {
	s.Length = uint16(len(s.String) + 1)
	ret := []byte{}
	binary.LittleEndian.PutUint16(ret, s.Length)
	stringpart := hex.EncodeToString([]byte(s.String)) + "00"
	lengthpart := hex.EncodeToString(ret)
	bytes, _ := hex.DecodeString(lengthpart + stringpart)
	return bytes
}

type NEXBuffer struct {
	Length uint32
	Data   []byte
}

func (b NEXBuffer) FromBytes(params []byte) NEXBuffer {
	b.Length = binary.LittleEndian.Uint32(params[0:])
	b.Data = params[4 : len(params)-5]
	return b
}

func (b NEXBuffer) Bytes() []byte {
	buff := make([]byte, 4)
	b.Length = uint32(len(b.Data))
	binary.LittleEndian.PutUint32(buff, b.Length)
	return append(buff, b.Data...)
}

// DataHolder represents a generic data holder
type DataHolder struct {
	Name       string
	Length     uint32
	DataLength uint32
	Data       []byte
}

type Variant struct {
	// TODO: fill out Variant.
}

// NewStationURL returns a new station URL string
func NewStationURL(protocol string, JSON map[string]string) string {
	var URLBuffer bytes.Buffer

	URLBuffer.WriteString(protocol + ":/")

	for key, value := range JSON {
		option := key + "=" + value + ";"
		URLBuffer.WriteString(option)
	}

	URL := URLBuffer.String()
	URL = strings.TrimRight(URL, ";")

	return URL
}

// Kerberos represents a basic Kerberos handling struct
type Kerberos struct {
	Key string
}

// Decrypt decrypts the data of Kerberos response
func (encryption *Kerberos) Decrypt(buffer []byte) []byte {
	if !encryption.Validate(buffer) {
		fmt.Println("INVALID KERB CHECKSUM")
	}

	offset := len(buffer)
	offset = offset + -0x10

	data := buffer[:offset]

	_key, _ := hex.DecodeString(encryption.Key)
	RC4, _ := rc4.NewCipher(_key)

	crypted := make([]byte, len(data))
	RC4.XORKeyStream(crypted, data)

	return crypted
}

// Encrypt encrypts the data of Kerberos request
func (encryption *Kerberos) Encrypt(buffer []byte) []byte {
	_key, _ := hex.DecodeString(encryption.Key)
	RC4, _ := rc4.NewCipher(_key)

	crypted := make([]byte, len(buffer))
	RC4.XORKeyStream(crypted, buffer)

	cipher := hmac.New(md5.New, _key)
	cipher.Write(crypted)
	checksum := cipher.Sum(nil)

	return append(crypted, checksum...)
}

// Validate validates the Kerberos data
func (encryption *Kerberos) Validate(buffer []byte) bool {
	offset := len(buffer)
	offset = offset + -0x10

	data := buffer[:offset]
	checksum := buffer[offset:]

	_key, _ := hex.DecodeString(encryption.Key)

	cipher := hmac.New(md5.New, _key)
	cipher.Write(data)
	mac := cipher.Sum(nil)

	return bytes.Equal(mac, checksum)
}

// NewKerberos returns a new instances of basic Kerberos
func NewKerberos(pid uint32, password string) Kerberos {
	key := []byte(password)
	for i := 0; uint32(i) < 65000+pid%1024; i++ {
		key = MD5Hash(key)
	}
	//fmt.Println("key " + hex.EncodeToString(key))
	return Kerberos{
		Key: string(hex.EncodeToString(key)),
	}
}

type Ticket struct {
	SessionKey []byte
	PID        uint32
	TicketData []byte
}

func NewTicket(session_key []byte, pid uint32, ticketdat []byte) Ticket {
	return Ticket{
		SessionKey: session_key,
		PID:        pid,
		TicketData: ticketdat,
	}
}

func (t Ticket) Encrypt(pid uint32, pass string) []byte {
	kerb := NewKerberos(pid, pass)
	outputstr := NewOutputStream()
	outputstr.Write(t.SessionKey)
	outputstr.UInt32LE(t.PID)
	outputstr.Buffer(t.TicketData)
	return kerb.Encrypt(outputstr.Bytes())
}

// MD5Hash returns the MD5 hash of the input
func MD5Hash(text []byte) []byte {
	hasher := md5.New()
	hasher.Write(text)
	return hasher.Sum(nil)
}
