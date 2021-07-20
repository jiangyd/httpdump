package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket/layers"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	GET     = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420" // 47455420 为 GET 的十六进制(GET后面带空格)
	POST    = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354" //504f5354 为POST的十六进制
	PUT     = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420"
	HEAD    = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144"
	DELETE  = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45" // 44454c45 为  DELE的十六进制
	PATCH   = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443"
	OPTIONS = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449"
	CONNECT = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e"
	HTTP = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450"
)

func main() {
	var dev = flag.String("dev", "any", "interface example: eth0")
	var method = flag.String("methods", "", "methods name example: GET or GET|POST")
	var ip = flag.String("ip", "", "source ip or dst ip")
	var port = flag.String("port", "", "src port or dst port")
	var path = flag.String("path", "", "url request path")

	//flag.Usage= func() {
	//	fmt.Println("capture http packge")
	//}
	flag.Parse()


	handle, err := pcap.OpenLive(*dev, 1600, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer handle.Close()

	bpf := "tcp"

	if len(*port) > 0 {
		bpf += " port " + *port
	}
	if len(*method) > 0 {
		ms := strings.Split(*method, "|")
		bpf += " and ( "+HTTP+" or "
		for _, m := range ms {
			switch strings.ToUpper(m) {
			case "GET":
				bpf += GET + " or "
			case "POST":
				bpf += POST + " or "
			case "PUT":
				bpf += PUT + " or "
			case "DELETE":
				bpf += DELETE + " or "
			case "HEAD":
				bpf += HEAD + " or "
			case "OPTIONS":
				bpf += OPTIONS + " or "
			case "PATCH":
				bpf += PATCH + " or "
			case "CONNECT":
				bpf += CONNECT + " or "
			}
		}
		bpf = strings.Trim(bpf, " ")
		bpf = strings.Trim(bpf, "or")
		bpf += " ) "
	}
	if len(*ip) > 0 {
		bpf += " and host " + *ip
	}

	fmt.Printf("bpf filter: %s\n", bpf)
	err = handle.SetBPFFilter(bpf)
	if err != nil {
		panic(err)
	}

	packge := gopacket.NewPacketSource(handle, handle.LinkType())

	for pk := range packge.Packets() {
		handlePacket(pk, *path)
	}

}

func handlePacket(p gopacket.Packet, path string) {
	httppack := p.ApplicationLayer()

	if httppack != nil {
		s := string(httppack.Payload())
		if strings.HasPrefix(s, "POST") || strings.HasPrefix(s, "GET") || strings.HasPrefix(s, "PUT") || strings.HasPrefix(s, "DELETE") || strings.HasPrefix(s, "HEAD") || strings.HasPrefix(s, "OPTIONS") || strings.HasPrefix(s, "PATCH") || strings.HasPrefix(s, "CONNECT") {


			payload := bytes.NewReader(httppack.Payload())
			payload_read := bufio.NewReader(payload)
			req, err := http.ReadRequest(payload_read)

			if err == nil {
				re, err := regexp.Compile(path)
				if err != nil {
					fmt.Println("regexp error")
				}
				if re.MatchString(req.URL.Path) {
					endpoint := p.NetworkLayer().NetworkFlow()
					tcplayer := p.Layer(layers.LayerTypeTCP)
					tcp, _ := tcplayer.(*layers.TCP)
					fmt.Println("\n")
					fmt.Print(endpoint.Src().String() + ":" + tcp.SrcPort.String())
					fmt.Print("->")
					fmt.Print(endpoint.Dst().String() + ":" + tcp.DstPort.String())
					fmt.Println("\n")
					fmt.Println(s)

					//data := make([]byte, 1024)
					//count := 0
					//for {
					//	len, err := req.Body.Read(data)
					//	if err == io.EOF {
					//		break
					//	}
					//	count += len
					//}
					//
					//fmt.Println(string(data[:count]))
					//count = 0
				}
			}
		} else if strings.HasPrefix(s, "HTTP/1") {
			endpoint := p.NetworkLayer().NetworkFlow()
			tcplayer := p.Layer(layers.LayerTypeTCP)
			tcp, _ := tcplayer.(*layers.TCP)
			fmt.Println("\n")
			fmt.Print(endpoint.Src().String() + ":" + tcp.SrcPort.String())
			fmt.Print("->")
			fmt.Print(endpoint.Dst().String() + ":" + tcp.DstPort.String())
			fmt.Println("\n")

			fmt.Println(s)

			//if e == nil {
			//
			//data := make([]byte, 1024)
			//count := 0
			//for {
			//	len, err := resp.Body.Read(data)
			//	if err == io.EOF {
			//		break
			//	}
			//	count += len
			//}
			//
			//fmt.Println(string(data[:count]))
			//count = 0
			//}
		}

	}

}
