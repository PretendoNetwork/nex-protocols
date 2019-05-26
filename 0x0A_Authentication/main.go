package NEXProtocol0x0A

import (
	"encoding/hex"
	"fmt"
	"strconv"

	Common "../common"
)

type InitOptions struct {
	SecureServerIP   string
	SecureServerPort string
	MongoIP          string
	MongoPort        string
	MongoPassword    string
}

var initialized = true
var protocoloptions = InitOptions{}

func InitProtocol(options InitOptions) bool {
	protocoloptions = options
	initialized = true
	return true
}

// just return errors for now for testing purposes
func Login(params []byte) ([]byte, uint32) {
	/*if !initialized {
		return nil, uint32(0xFFFFFFFF)
	}*/
	username := Common.NEXString{}.FromBytes(params)
	fmt.Println("User \"" + username.String + "\" is trying to authenticate...")
	usrpid, _ := strconv.ParseUint(username.String, 10, 32)
	//fmt.Println(usrpid)

	//build response data
	outstream := Common.NewOutputStream()

	//add result code
	resultcode := uint32(0x00010001)
	outstream.UInt32LE(resultcode)

	//add user pid
	outstream.UInt32LE(uint32(usrpid))

	//add Kerberos ticket
	buffer, _ := hex.DecodeString("100000002e71a7d60d41233d942e5d1306e262a72c000000bc3de22f0eac8337fcea49ccca4bce0dbfcd23f8c168fc6661a823750277161a858644ed3ce191e510bdd960")
	tik := Common.NewTicket(make([]byte, 16), 0x00000001, buffer)
	fmt.Println(hex.EncodeToString(tik.Encrypt(uint32(usrpid), "WDQuTAQaOJ4lCt8t")))
	outstream.Buffer(tik.Encrypt(uint32(usrpid), "WDQuTAQaOJ4lCt8t"))

	//add RVConnectionData
	outstream.String("prudp:/stream=10;type=2;PID=2;port=60001;address=192.168.137.1;sid=1;CID=1")
	outstream.UInt32LE(0x00000000)
	outstream.String("")

	//add Server name
	outstream.String("branch:origin/feature/45925_FixAutoReconnect build:3_10_11_2006_0")

	return outstream.Bytes(), resultcode
}

func RequestTicket(params []byte) ([]byte, uint32) {
	instream := Common.NewInputStream(params)
	usrpid := instream.UInt32LE()
	//secservpid := instream.UInt32LE()

	fmt.Println("User \"" + string(usrpid) + "\" is requesting the secure server ticket...")

	//build response data
	outstream := Common.NewOutputStream()

	//add result code
	resultcode := uint32(0x00010001)
	outstream.UInt32LE(resultcode)

	//add Kerberos ticket
	buffer, _ := hex.DecodeString("100000002e71a7d60d41233d942e5d1306e262a72c000000bc3de22f0eac8337fcea49ccca4bce0dbfcd23f8c168fc6661a823750277161a858644ed3ce191e510bdd960")
	tik := Common.NewTicket(make([]byte, 16), 0x00000001, buffer)
	fmt.Println(hex.EncodeToString(tik.Encrypt(uint32(usrpid), "WDQuTAQaOJ4lCt8t")))
	outstream.Buffer(tik.Encrypt(uint32(usrpid), "WDQuTAQaOJ4lCt8t"))

	return outstream.Bytes(), resultcode
}
