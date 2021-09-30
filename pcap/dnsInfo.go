package pcap

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/google/gopacket/layers"
)

const (
	DNS_TCP_PORT          = 53
	ERROR_NOT_DNS         = -53
	MIN_DNS_ANSWER_LENGTH = 16
)

type ethernetHeader struct {
	SourceMac string
	DestMac   string
	Etype     uint16
}

type ipHeader struct {
	SourceIP string
	DestIP   string
	Protocol uint8
}

type transportHeader struct {
	SourcePort uint16
	DestPort   uint16
}

type result struct {
	Name  string
	Ip    string
	Type  layers.DNSType
	Class string
	Cname string
}

type dnsPayload struct {
	TransactionID uint16
	answers       []result
	Err           string
	QueryName     string
}

type dnsAnswer struct {
	ethernetHeader
	ipHeader
	transportHeader
	dnsPayload
	RequesTime string
	Time       int64 // Unix micro
}

/*
func (alias *dnsQuery) printData() {
	fmt.Printf("[%s] [%s]:[%d] -> [%s]:[%d] FOR [%s] - Proto[%v] - Type[%s] - Class[%s]\n", alias.Time, alias.SourceIP, alias.SourcePort, alias.DestIP, alias.DestPort, alias.Name, alias.Protocol, alias.Type, alias.Class)
}
*/
func (alias *dnsAnswer) logData() string {
	var buff bytes.Buffer
	//buff.WriteString(alias.Time)
	buff.WriteString(" # ")
	for i, value := range alias.answers {
		if i != 0 {
			buff.WriteString(", ")
		}
		buff.WriteString(value.Name)
		buff.WriteString(" -> ")
		if value.Type == layers.DNSTypeCNAME {
			buff.WriteString(value.Cname)
		} else {
			buff.WriteString(value.Ip)
		}
	}

	return buff.String()
}

func (alias *dnsAnswer) extractData() []map[string]string {
	var records []map[string]string
	var time string

	if len(alias.Err) > 1 {
		time = fmt.Sprintf("%v", alias.Time)
		records = append(records, map[string]string{
			"Time":     time,
			"Name":     alias.QueryName, // show the name from error dns resp
			"Type":     "ERROR",
			"IP_CNAME": alias.Err, // show error instead of address info
			"Protocol": strconv.Itoa(int(alias.Protocol)),
		},
		)
		return records
	}

	for _, value := range alias.answers {
		var infor string
		if value.Type == layers.DNSTypeCNAME {
			infor = value.Cname
		} else {
			infor = value.Ip
		}

		time = fmt.Sprintf("%v", alias.Time)
		records = append(records, map[string]string{
			"Time":     time,
			"Name":     value.Name,
			"Type":     value.Type.String(),
			"IP_CNAME": infor,
			"Protocol": strconv.Itoa(int(alias.Protocol)),
		},
		)
	}
	return records
}
