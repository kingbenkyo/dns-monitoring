/**
 * @file pcap_dns_util.go
 * @author kingbenkyo@gmail.com
 * @brief this program is to filter DNS response over TCP and UDP
 * @version 0.1
 * @date 2021-09-30
 *
 * @copyright Copyright (c) 2021
 */
package pcap

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	//deviceName  string = "usb0"
	snapshotLen uint32 = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	locker      *sync.Mutex
	storedData  map[uint16]dnsAnswer
)

func Start(deviceName string) error {
	locker = new(sync.Mutex)

	handle, err = pcap.OpenLive(deviceName, int32(snapshotLen), promiscuous, timeout)
	if err != nil {
		return err
	}

	storedData = make(map[uint16]dnsAnswer)
	/**
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dns, err := extractPacketInfo(packet)
		if err != nil {
			//fmt.Printf("error: %v\n", err)
		} else {
			//dns.printData()
			fmt.Println(dns.logData())
			//saveData(*dns)
		}
	}
	*/
	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			dns, err := extractPacketInfo(packet)
			if err != nil {
				//fmt.Printf("error: %v\n", err)
			} else {
				//dns.printData()
				//fmt.Println(dns.logData())
				saveData(*dns)
			}
		}
	}()

	return nil
}

func Close() {
	handle.Close()
	fmt.Println("Close DNS filter")
}

func saveData(dns dnsAnswer) {
	locker.Lock()
	defer locker.Unlock()

	storedData[dns.TransactionID] = dns // use transaction id as the key
}

func GetData() []map[string]string {
	locker.Lock()

	defer locker.Unlock()

	var results []map[string]string

	// Copy from the original map to the target map
	for key, value := range storedData {
		results = append(results, value.extractData()...)
		delete(storedData, key) // remove
	}
	return results
}

func extractPacketInfo(packet gopacket.Packet) (*dnsAnswer, error) {
	dns := dnsAnswer{}
	//fmt.Printf("Time %v\n", packet.Metadata().CaptureInfo.Timestamp.UnixMicro())
	dns.Time = packet.Metadata().CaptureInfo.Timestamp.UnixNano()

	// Extract ethernet header
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	isIpv6 := false

	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		dns.SourceMac = string(ethernetPacket.SrcMAC[:])
		dns.DestMac = string(ethernetPacket.DstMAC[:])
		dns.Etype = uint16(ethernetPacket.EthernetType)

		if ethernetPacket.EthernetType == layers.EthernetTypeIPv4 {
			isIpv6 = false
		} else if ethernetPacket.EthernetType == layers.EthernetTypeIPv6 {
			isIpv6 = true
		} else {
			return nil, errors.New("not support ethernet type")
		}

	} else {
		return nil, errors.New("not ethernet package")
	}

	// Extract IP header
	var protocol layers.IPProtocol
	if isIpv6 {
		ipLayer := packet.Layer(layers.LayerTypeIPv6)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			dns.SourceIP = ip.SrcIP.String()
			dns.DestIP = ip.DstIP.String()
			protocol = ip.NextHeader
		} else {
			return nil, errors.New("cannot extract ipv6 header")
		}
	} else {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			dns.SourceIP = ip.SrcIP.String()
			dns.DestIP = ip.DstIP.String()
			protocol = ip.Protocol
		} else {
			return nil, errors.New("cannot extract ipv4 header")
		}
	}

	dns.Protocol = uint8(protocol)

	// Extract transport header
	if protocol == layers.IPProtocolTCP {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, status := tcpLayer.(*layers.TCP)
			if !status {
				return nil, errors.New("cannot extract transport as tcp")
			}
			dns.SourcePort = uint16(tcp.SrcPort)
			dns.DestPort = uint16(tcp.DstPort)
		} else {
			return nil, errors.New("cannot form tcp")
		}
	} else if protocol == layers.IPProtocolUDP {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, status := udpLayer.(*layers.UDP)
			if !status {
				return nil, errors.New("cannot extract transport as udp")
			}
			dns.SourcePort = uint16(udp.SrcPort)
			dns.DestPort = uint16(udp.DstPort)
		} else {
			return nil, errors.New("cannot form udp")
		}

	} else {
		return nil, errors.New("cannot not match transport protocol")
	}

	// Extract DNS Response
	var dnsResp *layers.DNS = nil
	var status bool = false
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dnsResp, status = dnsLayer.(*layers.DNS)
		if !status {
			return nil, errors.New("cannot extract dns package")
		}
	} else {
		if dns.SourcePort == DNS_TCP_PORT && protocol == layers.IPProtocolTCP { // filter for TCP with source Port 53 - As DNS response
			if packet.ApplicationLayer() == nil {
				return nil, errors.New("not target dns. empty body") // maybe ACK or SYN
			}

			tcpPayload := packet.ApplicationLayer().Payload()
			if len(tcpPayload) <= MIN_DNS_ANSWER_LENGTH {
				fmt.Println("Invalid raw data: " + string(tcpPayload))
				return nil, errors.New("not target dns. invalid data size")
			}

			// 2 bytes for dns response length as tcp package design
			dnsAnswerLength := uint16(tcpPayload[0]*16 + tcpPayload[1])
			if len(tcpPayload) < (int(dnsAnswerLength + 2)) {
				fmt.Println("Invalid raw data - not enough: " + string(tcpPayload))
				return nil, errors.New("not target dns. invalid data size. not enough")
			}

			// There could be other part following DNS query answer like Additional records. Then just copy the DNS Answer part
			dnsAnswerContent := packet.ApplicationLayer().Payload()[2 : dnsAnswerLength+2] // get only dnsAnswerLength bytes

			dnsResp = &layers.DNS{}
			var payload *gopacket.Payload = &gopacket.Payload{}

			//for parsing the reassembled TCP streams
			dnsParser := gopacket.NewDecodingLayerParser(
				layers.LayerTypeDNS,
				dnsResp,
				payload,
			)

			transportLayerTypes := []gopacket.LayerType{layers.LayerTypeTCP} // just care about TCP
			err := dnsParser.DecodeLayers(dnsAnswerContent, &transportLayerTypes)

			if err != nil {
				return nil, errors.New("not dns package over tcp - cannot parse")
			}
		} else {
			return nil, errors.New("not dns package")
		}
	}

	dns.TransactionID = dnsResp.ID

	if dnsResp.ResponseCode != layers.DNSResponseCodeNoErr {
		dns.QueryName = string(dnsResp.Questions[0].Name)
		dns.Err = dnsResp.ResponseCode.String()
		fmt.Println("Error: " + dns.Err + "  " + dns.QueryName)
		return &dns, nil
	}

	if dnsResp.QR { // this is response
		// filter for response
	} else {
		// this is request
		return nil, errors.New("it is a dns-request")
	}

	//if dnsResp.ResponseCode != 0 {
	//	return nil, errors.New("dns response as error" + dnsResp.ResponseCode.String())
	//}

	for _, answer := range dnsResp.Answers {
		tmp := result{Ip: answer.IP.String(), Type: answer.Type, Class: answer.Class.String(), Name: string(answer.Name), Cname: string(answer.CNAME)}
		dns.answers = append(dns.answers, tmp)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		return nil, errors.New("checking error")
	}

	return &dns, nil
}
