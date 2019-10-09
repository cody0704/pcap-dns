package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"import/file"
	"log"
	"regexp"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	_ "github.com/go-sql-driver/mysql"
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

var conn *sql.DB

func main() {
	path := flag.String("path", "", "file path")
	user := flag.String("user", "root", "mysql user")
	pass := flag.String("pass", "toor", "mysql pass")
	host := flag.String("host", "127.0.0.1", "mysq host")
	port := flag.String("port", "3306", "mysql port")
	database := flag.String("db", "pcap", "mysql database")

	flag.Parse()

	if *path == "" {
		fmt.Println(`please add --path="<path>"`)
		return
	}

	root := file.GetAllFile(*path, "pcap")
	if len(root) == 0 {
		fmt.Println("Not found file or directory.")
	} else {
		conn = DBConnection(*user, *pass, *host, *port, *database)

		for _, temp := range root {
			handler, err := pcap.OpenOffline(*temp.Directory)
			if err != nil {
				log.Fatal(err)
			}

			defer handler.Close()

			packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

			for packet := range packetSource.Packets() {
				dns, err := test2Info(packet)
				if err == nil {
					// fmt.Printf("%s:%s - %s:%s [FQDN]: %s\n", dns.SrcIP, dns.SrcPort, dns.DstIP, dns.DstPort, dns.FQDN)
					status := dnsin2db(dns)
					if !status {
						fmt.Println("DB Write Failed")
					}
				}
			}
		}

		conn.Close()
	}
}

func DBConnection(user, pass, host, port, database string) *sql.DB {
	var connectionString = fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?allowNativePasswords=true", user, pass, host, port, database)

	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		fmt.Println("[Mysql][Error]:", err)
	}

	err = db.Ping()
	if err != nil {
		fmt.Println("[Mysql][Error]: No Response")
	}

	return db
}

func dnsin2db(dns Test2Struct) bool {

	res, err := conn.Exec("INSERT INTO `dns`(`Date`, `Time`, `usec`, `SourceIP`, `SourcePort`, `DestinationIP`, `DestinationPort`, `FQDN`) VALUES (?,?,?,?,?,?,?,?);", dns.Date, dns.Time, dns.usec, dns.SrcIP, getPort(dns.SrcPort), dns.DstIP, getPort(dns.DstPort), dns.FQDN)
	if err != nil {
		fmt.Println(err)
	}

	rowCount, _ := res.RowsAffected()
	if rowCount == 1 {
		return true
	}

	return false
}

func getPort(pacpPort string) (port string) {
	re, _ := regexp.Compile(`^(\d+)`)
	port = string(re.Find([]byte(pacpPort)))

	return
}
