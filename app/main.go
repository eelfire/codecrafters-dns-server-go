package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	var resolverAddr string
	flag.StringVar(&resolverAddr, "resolver", "", "specify resolver")

	var port string
	flag.StringVar(&port, "port", "2053", "specify port")
	flag.Parse()

	fmt.Println("resolverAddr: ", resolverAddr)

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
	// fmt.Println(DecodeName(EncodeName("codecrafters.io")))

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
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

	forwardAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	if err != nil {
		fmt.Println("Failed to resolve UDP address of resolver", err)
		return
	}
	resolverConn, err := net.DialUDP("udp", nil, forwardAddr)
	if err != nil {
		return
	}
	defer resolverConn.Close()

	// var forwardAddr *net.UDPAddr
	// var dialConn *net.UDPConn
	// if resolverAddr != "" {
	// forwardAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	// if err != nil {
	// 	fmt.Println("Failed to resolve UDP address of resolver", err)
	// 	return
	// }
	// dialConn, err = net.DialUDP("udp", nil, forwardAddr)
	// if err != nil {
	// 	fmt.Println("Failed to bind to UDP address of resolver", err)
	// 	return
	// }
	// defer dialConn.Close()
	// }

	buf := make([]byte, 512)
	// buf2 := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		// fmt.Printf("%x\n", buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)
		dnsReceived := DecodeDnsResponse(buf[:])

		// Create an empty response
		dnsMessage := DnsMessage{
			hdr:  NewHeader(),
			ques: []Question{},
			ans:  []Answer{},
		}

		// need to improve this very much
		dnsMessage.hdr.id = binary.BigEndian.Uint16(buf[0:2])
		// mask := // 01111001 00000000
		opcode := byte((buf[2] << 1) >> 4)
		rd := byte(buf[2] & 1)
		var rcode byte
		if opcode == 0 {
			rcode = 0
		} else {
			rcode = 4
		}
		x := byte(0)
		if rd == 1 {
			x = 129
		} else {
			x = 128
		}
		// fmt.Println(x)
		dnsMessage.hdr.flags = [2]byte{byte((opcode << 3) | x), rcode}
		// fmt.Printf("\t-->>%x\n", dnsMessage.hdr.flags)

		// respName := DecodeName(buf[12:])
		// respName := ParseCompressed(buf[:])
		// dnsMessage.ques[0].name = respName
		// dnsMessage.ans[0].name = respName
		qdcount := dnsReceived.hdr.qdcount
		dnsMessage.hdr.qdcount = qdcount
		dnsMessage.hdr.ancount = qdcount

		// fmt.Println(qdcount)
		for i := uint16(0); i < qdcount; i++ {
			fmt.Println("appending ques in dnsMessage, i = ", i)
			ques := NewQuestion()
			ques.name = dnsReceived.ques[i].name
			dnsMessage.ques = append(dnsMessage.ques, ques)

			// if resolverAddr != "" {
			// 	rDnsReceived, _ := ForwardRequest(buf[:], resolverAddr)
			// 	dnsMessage.ans = append(dnsMessage.ans, rDnsReceived.ans...)
			// } else {
			// 	for i := uint16(0); i < qdcount; i++ {
			// 		fmt.Println("c0c0c0c0c0c0", i)
			// 		ans := NewAnswer()
			// 		ans.name = dnsReceived.ques[i].name
			// 		dnsMessage.ans = append(dnsMessage.ans, ans)
			// 	}
			// }
		}

		for i := uint16(0); resolverAddr == "" && i < qdcount; i++ {
			fmt.Println("appending ans in dnsMessage, i = ", i)
			ans := NewAnswer()
			ans.name = dnsReceived.ques[i].name
			dnsMessage.ans = append(dnsMessage.ans, ans)
		}

		if resolverAddr != "" {
			if qdcount <= 1 {
				fmt.Println("buffer len: ", len(buf))
				rDnsReceived, _ := ForwardRequest(buf[:], resolverConn)
				dnsMessage.ans = rDnsReceived.ans
			} else {
				for i := uint16(0); i < qdcount; i++ {
					tmpMsg := DnsMessage{
						hdr:  NewHeader(),
						ques: []Question{},
						ans:  []Answer{},
					}
					tmpMsg.hdr = dnsMessage.hdr
					tmpMsg.hdr.qdcount = 1
					tmpMsg.hdr.ancount = 0
					tmpMsg.ques = append(tmpMsg.ques, dnsMessage.ques[i])
					tmpBuf := GenDnsResponeWithoutAns(tmpMsg)
					// tmpBuf[0:12] = buf[0:12]
					copy(tmpBuf[0:12], buf[0:12])
					tmpBuf[5] = 1
					fmt.Println("ith: ", i, "tmpBuf: ", tmpBuf)

					rDnsReceived, _ := ForwardRequest(tmpBuf[:], resolverConn)
					dnsMessage.ans = append(dnsMessage.ans, rDnsReceived.ans...)
				}
			}

		}

		// fmt.Println("\n\n----0o0o0o0o--\n", dnsMessage, "\n\n---0o0o0o0o---")

		fmt.Println("final qdcount", dnsMessage.hdr.qdcount, "-- final ancount", dnsMessage.hdr.ancount, "| addr: ", source)
		response := GenDnsRespone(dnsMessage)
		// response := []byte{}
		// fmt.Printf("%x\n", response)
		// fmt.Println("dns response: ", response, len(response))
		fmt.Println("dns response len: ", len(response))

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func ForwardRequest(request []byte, resolverConn *net.UDPConn) (DnsMessage, error) {
	dnsMessage := DnsMessage{}
	response := make([]byte, 512)

	// forwardAddr, err := net.ResolveUDPAddr("udp", resolverAddr)
	// if err != nil {
	// 	fmt.Println("Failed to resolve UDP address of resolver", err)
	// 	return dnsMessage, err
	// }
	// conn, err := net.DialUDP("udp", nil, forwardAddr)
	// if err != nil {
	// 	return dnsMessage, err
	// }
	// defer conn.Close()

	// for {
	// 	_, err = conn.WriteToUDP(request, forwardAddr)
	// 	if err != nil {
	// 		return dnsMessage, err
	// 	}
	//
	// 	size, source, err := conn.ReadFromUDP(response)
	// 	fmt.Println(size, source)
	// 	if err != nil {
	// 		fmt.Println("Error receiving data:", err)
	// 		return dnsMessage, err
	// 	} else {
	// 		break
	// 	}
	//
	// }

	_, err := resolverConn.Write(request)
	if err != nil {
		return dnsMessage, err
	}

	// time.Sleep(time.Millisecond * 1000)
	n, err := resolverConn.Read(response)
	// _, _, err = conn.ReadFromUDP(response)
	if err != nil {
		return dnsMessage, err
	}

	// fmt.Println(n, "resolver response: ", response)
	fmt.Println("number of bytes read from resolver", n)
	dnsMessage = DecodeDnsResponseWithAnswer(response)
	// fmt.Println("\n\n------", dnsMessage, "\n\n------")
	// fmt.Println("*(***((y)))", dnsMessage.ans)

	return dnsMessage, nil
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
	fmt.Println("in GenDnsHeaderResponse (qdcount, ancount): (", hdr.qdcount, hdr.ancount, ")")
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

// func DecodeName(buf []byte) string {
// 	name := ""
// 	i := 0
// 	for i < len(buf) {
// 		length := int(buf[i])
// 		if length == 0 {
// 			break
// 		}
// 		i++
// 		name += string(buf[i:i+length]) + "."
// 		i += length
// 	}
// 	return strings.TrimSuffix(name, ".")
// }

func ParseCompressed(buf []byte) string {
	name := ""
	i := 12
	for i < len(buf) {
		length := int(buf[i])
		if length == 0 {
			break
		}
		if length >= 192 {
			offset := int(binary.BigEndian.Uint16([]byte{buf[i], buf[i+1]}) ^ 0xC000)
			// offset += 12
			name += ParseCompressed(buf[offset:])
			break
		}
		i++
		name += string(buf[i:i+length]) + "."
		i += length
	}
	return strings.TrimSuffix(name, ".")
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
	ques []Question
	ans  []Answer
}

func GenDnsRespone(msg DnsMessage) []byte {
	resp := []byte{}
	resp = append(resp, GenDnsHeaderResponse(msg.hdr)...)
	for _, q := range msg.ques {
		resp = append(resp, GenDnsQuestionResponse(q)...)
	}
	for _, a := range msg.ans {
		// fmt.Println("over here")
		resp = append(resp, GenDnsAnswerResponse(a)...)
	}

	return resp
}

func GenDnsResponeWithoutAns(msg DnsMessage) []byte {
	resp := []byte{}
	resp = append(resp, GenDnsHeaderResponse(msg.hdr)...)
	for _, q := range msg.ques {
		resp = append(resp, GenDnsQuestionResponse(q)...)
	}

	return resp
}

func DecodeDnsResponse(buf []byte) DnsMessage {
	dnsMessage := DnsMessage{
		hdr:  NewHeader(),
		ques: []Question{NewQuestion()},
		ans:  []Answer{NewAnswer()},
	}

	// Decode the header
	headerSize := 12 // Size of the DNS header
	headerBytes := buf[:headerSize]
	dnsMessage.hdr = DecodeDnsHeader(headerBytes)

	qdcount := dnsMessage.hdr.qdcount
	ancount := dnsMessage.hdr.ancount
	fmt.Println("qdcount (w/o ans): ", qdcount)
	fmt.Println("ancount (w/o ans): ", ancount)

	// Decode the questions
	// questionBytes := buf[headerSize:]
	questionBytes := buf[:]
	// offset := 0
	dnsMessage.ques, _ = DecodeDnsQuestions(questionBytes, qdcount)
	// fmt.Println(dnsMessage.ques)

	// Decode the answers
	// answerBytes := buf[headerSize+offset+1:]
	// dnsMessage.ans = DecodeDnsAnswers(answerBytes, ancount)

	return dnsMessage
}

func DecodeDnsResponseWithAnswer(buf []byte) DnsMessage {
	dnsMessage := DnsMessage{
		hdr:  NewHeader(),
		ques: []Question{NewQuestion()},
		ans:  []Answer{NewAnswer()},
	}

	// Decode the header
	headerSize := 12 // Size of the DNS header
	headerBytes := buf[:headerSize]
	dnsMessage.hdr = DecodeDnsHeader(headerBytes)

	qdcount := dnsMessage.hdr.qdcount
	ancount := dnsMessage.hdr.ancount
	fmt.Println("qdcount (w/ ans): ", qdcount)
	fmt.Println("qdcount (w/ ans): ", ancount)

	// Decode the questions
	// questionBytes := buf[headerSize:]
	questionBytes := buf[:]
	offset := 0
	dnsMessage.ques, offset = DecodeDnsQuestions(questionBytes, qdcount)
	// fmt.Println(dnsMessage.ques)

	// Decode the answers
	answerBytes := buf[offset:]
	dnsMessage.ans = DecodeDnsAnswers(answerBytes, ancount)

	return dnsMessage
}

func DecodeDnsHeader(buf []byte) DnsHeader {
	fmt.Println("in DecodeDnsHeader buf: ", buf)
	header := DnsHeader{}
	header.id = binary.BigEndian.Uint16(buf[0:2])
	copy(header.flags[:], buf[2:4])
	header.qdcount = binary.BigEndian.Uint16(buf[4:6])
	header.ancount = binary.BigEndian.Uint16(buf[6:8])
	header.nscount = binary.BigEndian.Uint16(buf[8:10])
	header.arcount = binary.BigEndian.Uint16(buf[10:12])
	fmt.Println("in DecodeDnsHeader: ", header)
	return header
}

func DecodeDnsQuestions(buf []byte, qdcount uint16) ([]Question, int) {
	questions := []Question{}
	// offset := 0
	offset := 12
	count := uint16(0)
	for offset < len(buf) {
		question := Question{}
		// fmt.Println(offset)
		question.name, offset = DecodeName(buf, offset)
		copy(question.typ[:], buf[offset:offset+2])
		copy(question.class[:], buf[offset+2:offset+4])
		questions = append(questions, question)
		offset += 4

		// fmt.Println("here")
		count++
		if count == qdcount {
			break
		}

	}
	return questions, offset
}

func DecodeDnsAnswers(buf []byte, count uint16) []Answer {
	answers := []Answer{}
	offset := 0
	for offset < len(buf) {
		answer := Answer{}
		answer.name, offset = DecodeName(buf, offset)
		answer.typ = binary.BigEndian.Uint16(buf[offset : offset+2])
		answer.class = binary.BigEndian.Uint16(buf[offset+2 : offset+4])
		answer.ttl = binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		answer.rdlength = binary.BigEndian.Uint16(buf[offset+8 : offset+10])
		answer.rdata = buf[offset+10 : offset+10+int(answer.rdlength)]
		// fmt.Println("there")
		answers = append(answers, answer)
		// break
		offset += 10 + int(answer.rdlength)

		if count != 0 {
			count--
		}
		if count == 0 {
			break
		}
	}
	return answers
}

func DecodeName(buf []byte, offset int) (string, int) {
	name := ""
	for {
		// fmt.Println("is it me?")
		length := int(buf[offset])
		if length == 0 {
			break
		}
		if len(name) > 0 {
			name += "."
		}
		if length >= 192 {
			pointerOffset := binary.BigEndian.Uint16(buf[offset : offset+2])
			pointerOffset &= 0x3FFF
			namePart, _ := DecodeName(buf, int(pointerOffset))
			name += namePart
			offset += 2
			break
		}
		offset += 1
		name += string(buf[offset : offset+length])
		offset += length
	}
	return name, offset + 1
}
