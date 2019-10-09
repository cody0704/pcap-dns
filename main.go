package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Test2Struct struct {
	Date    string
	Time    string
	usec    string
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	FQDN    string
}

func test2Info(packet gopacket.Packet) (d Test2Struct, err error) {
	//[DNS]
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {

		//[Ethernet Layer]
		d.Date = packet.Metadata().Timestamp.Format("2006-01-02")
		d.Time = packet.Metadata().Timestamp.Format("15:04:05")
		d.usec = strconv.Itoa(packet.Metadata().Timestamp.Nanosecond())

		//[IPv4 layer]
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			d.SrcIP = ip.SrcIP.String()
			d.DstIP = ip.DstIP.String()
		}

		//[UDP layer]
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			d.SrcPort = udp.SrcPort.String()
			d.DstPort = udp.SrcPort.String()
		}

		dns, _ := dnsLayer.(*layers.DNS)

		d.FQDN = string(dns.Questions[0].Name)

		err = nil
	} else {
		err = errors.New("This is not DNS")
	}

	return
}

func main() {
	path := flag.String("path", "./dns.pcap", "file path")
	flag.Parse()

	if _, err := os.Stat(*path); !os.IsNotExist(err) {
		handler, err := pcap.OpenOffline(*path)
		if err != nil {
			log.Fatal(err)
		}

		defer handler.Close()

		packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

		for packet := range packetSource.Packets() {
			dns, err := test2Info(packet)
			if err == nil {
				fmt.Printf("%s:%s - %s:%s [FQDN]: %s\n", dns.SrcIP, dns.SrcPort, dns.DstIP, dns.DstPort, dns.FQDN)
			}
		}
	} else {
		fmt.Println("file not exist!")
	}

}
