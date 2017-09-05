package main

import (
	//"crypto/rand"
	"flag"
	"fmt"
	//"io"
	"log"
	"net"
	"os"
	//"os/signal"
	//"syscall"

	//"github.com/matishsiao/go_reuseport"
	//"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

const (
	// AppVersion contains current application version for -version command flag
	AppVersion = "1.0.0"
)

const (
	// I use TUN interface, so only plain IP packet,
	// no ethernet header + mtu is set to 1300

	// BUFFERSIZE is size of buffer to receive packets
	// (little bit bigger than maximum)
	BUFFERSIZE = 1518
	MTU = "1300"
)

type Session struct {
	UserID [4]byte
	UDPDstPort int
	RemoteIP net.IP
	LocalIP net.IP
	LocalSrcPort int
	LocalDstPort int
	LocalProtocol [2]byte
}

func main() {
	version := flag.Bool("version", false, "print novpn version")
	listenAddrStr := flag.String("address","127.0.0.1","IP address to listen connections.")
	listenPort := flag.Int("port",444,"UDP port to listen..")
	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	log.Println(fmt.Sprintf("%s:%d",*listenAddrStr,*listenPort))
	listenAddr, err := net.ResolveUDPAddr("udp",fmt.Sprintf("%s:%d",*listenAddrStr,*listenPort))
	if nil != err {
		log.Fatalln("Invalid listen address:",err)
	}

	conn, err := net.ListenUDP("udp", listenAddr)
	if nil != err {
		log.Fatalln("Could not bind socket UDP/%d to",listenAddr,*listenPort)
	}
	defer conn.Close()
	log.Println("Started listening at",listenAddr,"port",*listenPort)

	//Recv Thread
	go func() {
		buf := make([]byte, BUFFERSIZE)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			header,_ := ipv4.ParseHeader(buf[:n])
			log.Println(fmt.Sprintf("Received %d bytes from %v: %+v",n,addr,header))
			if err != nil || n == 0 {
				log.Println("Error:",err)
			}
		}
	}()
}
