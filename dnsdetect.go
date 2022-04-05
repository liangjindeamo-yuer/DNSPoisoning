package main

import (
	"bufio"
	"fmt"
	"log"
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
		} else if element == "-r" {
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
	//如果是从文件中读取包
	if hostnames_file != "" {
		handle, err = pcap.OpenOffline(hostnames_file)
	} else {
		//如果没有文件
		handle, err = pcap.OpenLive(
			iface, //device
			int32(65535),
			true,
			-1*time.Second,
		)
	}

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
	var dnscache map[string][]layers.DNSResourceRecord
	dnscache = make(map[string][]layers.DNSResourceRecord)
	for packet := range packets {

		var eth layers.Ethernet
		var ip4 layers.IPv4
		var udp layers.UDP
		var dns layers.DNS

		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &udp, &dns)
		decodedLayers := []gopacket.LayerType{}
		parser.DecodeLayers(packet.Data(), &decodedLayers)

		var ID string = "ERWRN"
		var id int = 0
		//对于回复型DNS包
		if dns.QR && int(dns.Questions[0].Type) == 1 && dns.ANCount > 0 {
			//记录dns的域名
			if dnscache[string(dns.Questions[0].Name)] == nil {
				dnscache[string(dns.Questions[0].Name)] = dns.Answers
			} else {
				var len1 = 0
				var len2 = 0
				for _, v := range dnscache[string(dns.Questions[0].Name)] {
					if v.Type == layers.DNSTypeCNAME {
						continue
					} else {
						len1 += 1
					}
				}
				for _, v := range dns.Answers {
					if v.Type == layers.DNSTypeCNAME {
						continue
					} else {
						len2 += 1
					}
				}
				if len1 != len2 && len1 > 0 && len2 > 0 {
					var nowtime = time.Now().Format("2006-01-02 15:04:05")
					fmt.Printf("%s DNS poisoning attempt\n", nowtime)
					fmt.Printf("TXID:%s Request:%s\n", ID+string(rune(id)), string(dns.Questions[0].Name))
					var number int = 1
					for _, v := range dns.Answers {
						if v.Type == layers.DNSTypeCNAME {
							continue
						}
						fmt.Printf("Answer:%d\n", number)
						fmt.Println("Answers:", v.String())
						fmt.Println("Answers-name:", v.Type)
						number += 1
					}
					for _, v := range dnscache[string(dns.Questions[0].Name)] {
						if v.Type == layers.DNSTypeCNAME {
							continue
						}
						fmt.Printf("Answer:%d\n", number)
						fmt.Println("Answers:", v.String())
						fmt.Println("Answers-name:", v.Type)
						number += 1
					}
					id = id + 1
				} else if len1 > 0 && len2 > 0 {
					flag := 0
					for i := 0; i < len1; i++ {
						if dnscache[string(dns.Questions[0].Name)][i].IP.String() != dns.Answers[i].IP.String() {
							flag = 1
							break
						}
					}
					if flag == 1 {
						var nowtime = time.Now().Format("2006-01-02 15:04:05")
						fmt.Printf("%s DNS poisoning attempt\n", nowtime)
						fmt.Printf("TXID:%s Request:%s\n", ID+string(rune(id)), string(dns.Questions[0].Name))
						var number int = 1
						for _, v := range dns.Answers {
							if v.Type == layers.DNSTypeCNAME {
								continue
							}
							fmt.Printf("Answer:%d\n", number)
							fmt.Println("Answers:", v.String())
							fmt.Println("Answers-name:", v.Type)
							number += 1
						}
						for _, v := range dnscache[string(dns.Questions[0].Name)] {
							if v.Type == layers.DNSTypeCNAME {
								continue
							}
							fmt.Printf("Answer:%d\n", number)
							fmt.Println("Answers:", v.String())
							fmt.Println("Answers-name:", v.Type)
							number += 1
						}
						id = id + 1
						// TXID 0x5cce Request www.example.com
						// Answer1 [List of IP addresses]
						// Answer2 [List of IP addresses]
					}
				}
			}
		}

	}
}
