package main

import (
	"fmt"
	"net"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	// fmt.Println(GenDnsHeaderResponse(NewDnsHeader()))

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
		response := GenDnsHeaderResponse(NewDnsHeader())
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

func NewDnsHeader() DnsHeader {
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

// type DnsMessage struct {
// 	hdr DnsHeader
// }
