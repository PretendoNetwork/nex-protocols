
package NEXProtocol0x0A

import(
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

type NEXString struct {
	Length uint16
	String string
}

func (s NEXString) FromBytes(params []byte) NEXString {
	s.Length = binary.LittleEndian.Uint16(params[0:])
	s.String = string(params[1:len(params)-1])
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
	Data []byte
}

func (b NEXBuffer) FromBytes(params []byte) NEXBuffer {
	b.Length = binary.LittleEndian.Uint32(params[0:])
	b.Data = params[4:len(params)-5]
	return b
}

type InitOptions struct {
	SecureServerIP string
	SecureServerPort string
	MongoIP string
	MongoPort string
	MongoPassword string
}

var initialized = false
var protocoloptions = InitOptions{}

func InitProtocol(options InitOptions) bool {
	protocoloptions = options
	initialized = true
	return true
}

// just return errors for now for testing purposes
func Login(params []byte) ([]byte, uint32) {
	if !initialized {
		return nil, uint32(0xFFFFFFFF)
	}
	parameters := NEXString{}.FromBytes(params)
	fmt.Println("User " + parameters.String + " is trying to authenticate...")
	resultcode := uint32(0x8068000B)
	byteresult := []byte{0x0,0x0,0x0,0x0}
	binary.LittleEndian.PutUint32(byteresult, resultcode)
	return byteresult, resultcode
}