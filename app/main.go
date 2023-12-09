package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// fmt.Println(GenDnsHeaderResponse(NewDnsHeader()))
	// dnsMessage := DnsMessage{
	// 	hdr:  NewHeader(),
	// 	ques: NewQuestion(),
	// 	ans:  NewAnswer(),
	// }
	// msg := GenDnsRespone(dnsMessage)
	// fmt.Println(msg)
	// fmt.Println(string(msg))
	// fmt.Printf("%x\n", msg)
	// fmt.Println(byte(69))
	// fmt.Printf("%x\n", byte(69))

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		// fmt.Printf("%x\n", buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		dnsMessage := DnsMessage{
			hdr:  NewHeader(),
			ques: NewQuestion(),
			ans:  NewAnswer(),
		}
		dnsMessage.hdr.id = binary.BigEndian.Uint16(buf[0:2])
		// mask := // 01111001 00000000
		opcode := byte(buf[2] << 1 >> 3)
		var rcode byte
		if opcode == 0 {
			rcode = 0
		} else {
			rcode = 4
		}
		dnsMessage.hdr.flags = [2]byte{byte((opcode << 3) | 129), rcode}
		dnsMessage.hdr.qdcount += 1
		dnsMessage.hdr.ancount += 1
		response := GenDnsRespone(dnsMessage)
		// response := []byte{}

		// fmt.Printf("%x\n", response)

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

type DnsHeader struct {
	id      uint16  // 16 bits
	flags   [2]byte // 16 bits
	qdcount uint16  // 16 bits
	ancount uint16  // 16 bits
	nscount uint16  // 16 bits
	arcount uint16  // 16 bits
}

func NewHeader() DnsHeader {
	return DnsHeader{
		id:      1234,
		flags:   [2]byte{1 << 7, 0},
		qdcount: 0,
		ancount: 0,
		nscount: 0,
		arcount: 0,
	}
}

func GenDnsHeaderResponse(hdr DnsHeader) []byte {
	resp := []byte{
		byte(hdr.id >> 8), byte(hdr.id), // split uint16 into two bytes
		hdr.flags[0], hdr.flags[1],
		byte(hdr.qdcount >> 8), byte(hdr.qdcount),
		byte(hdr.ancount >> 8), byte(hdr.ancount),
		byte(hdr.nscount >> 8), byte(hdr.nscount),
		byte(hdr.arcount >> 8), byte(hdr.arcount),
	}
	// resp := []byte{}
	// resp = append(resp, byte(hdr.id))
	// resp = append(resp, hdr.flags[:]...)
	// resp = append(resp, byte(hdr.qdcount))
	// resp = append(resp, byte(hdr.ancount))
	// resp = append(resp, byte(hdr.nscount))
	// resp = append(resp, byte(hdr.arcount))
	return resp
}

type Question struct {
	name  string
	typ   [2]byte
	class [2]byte
}

func NewQuestion() Question {
	return Question{
		name:  "codecrafters.io",
		typ:   [2]byte{0, 1},
		class: [2]byte{0, 1},
	}
}

func EncodeName(name string) []byte {
	split := strings.Split(name, ".")
	resp := []byte{}
	for i := 0; i < len(split); i++ {
		resp = append(resp, byte(len(split[i])))
		resp = append(resp, []byte(split[i])...)
	}
	resp = append(resp, byte(00))
	return resp
}

func GenDnsQuestionResponse(ques Question) []byte {
	resp := append(EncodeName(ques.name), ques.typ[0], ques.typ[1], ques.class[0], ques.class[1])
	return resp
}

type Answer struct {
	name     string
	typ      uint16
	class    uint16
	ttl      uint32
	rdlength uint16
	rdata    []byte
}

func EncodeIp(ip string) []byte {
	split := strings.Split(ip, ".")
	resp := make([]byte, 4)
	for i := 0; i < 4; i++ {
		val, _ := strconv.Atoi(split[i])
		resp[i] = byte(val)
	}
	return resp
}

func NewAnswer() Answer {
	var RData [4]byte
	ip := uint32(0x08080808) // IP address: 8.8.8.8
	binary.BigEndian.PutUint32(RData[:], ip)
	return Answer{
		name:     "codecrafters.io",
		typ:      1,
		class:    1,
		ttl:      69,
		rdlength: 4,
		// rdata:    EncodeIp("8.8.8.8"),
		rdata: []byte{8, 8, 8, 8},
		// rdata: RData[:],
	}
}

func GenDnsAnswerResponse(ans Answer) []byte {
	resp := []byte{}
	resp = append(resp, EncodeName(ans.name)...)
	resp = append(resp, byte(ans.typ>>8), byte(ans.typ)) // Convert [2]byte to []byte
	resp = append(resp, byte(ans.class>>8), byte(ans.class))
	resp = append(resp, byte(ans.ttl>>24), byte(ans.ttl>>16), byte(ans.ttl>>8), byte(ans.ttl))
	resp = append(resp, byte(ans.rdlength>>8), byte(ans.rdlength))
	resp = append(resp, ans.rdata...)
	return resp

	// buff := new(bytes.Buffer)
	// binary.Write(buff, binary.BigEndian, ans)
	// return buff.Bytes()
}

type DnsMessage struct {
	hdr  DnsHeader
	ques Question
	ans  Answer
}

func GenDnsRespone(msg DnsMessage) []byte {
	resp := []byte{}
	resp = append(resp, GenDnsHeaderResponse(msg.hdr)...)
	resp = append(resp, GenDnsQuestionResponse(msg.ques)...)
	resp = append(resp, GenDnsAnswerResponse(msg.ans)...)

	return resp
}
