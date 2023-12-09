package main

import (
	"fmt"
	"net"
	"strings"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// fmt.Println(GenDnsHeaderResponse(NewDnsHeader()))
	// dnsMessage := DnsMessage{
	// 	hdr:  NewHeader(),
	// 	ques: NewQuestion(),
	// }
	// msg := GenDnsRespone(dnsMessage)
	// fmt.Println(msg)
	// fmt.Println(string(msg))
	// fmt.Printf("%x\n", msg)

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
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		dnsMessage := DnsMessage{
			hdr:  NewHeader(),
			ques: NewQuestion(),
		}
		response := GenDnsRespone(dnsMessage)
		// response := []byte{}

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

type DnsMessage struct {
	hdr  DnsHeader
	ques Question
}

func GenDnsRespone(msg DnsMessage) []byte {
	resp := append(GenDnsHeaderResponse(msg.hdr), GenDnsQuestionResponse(msg.ques)...)
	return resp
}
