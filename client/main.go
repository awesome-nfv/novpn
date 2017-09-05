package main

import (
//	"crypto/rand"
	"flag"
	"fmt"
//	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"bufio"
	"encoding/hex"
	"errors"
//	"os/signal"
	"syscall"
	"crypto/x509"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"encoding/json"

//	"github.com/matishsiao/go_reuseport"
	"github.com/songgao/water"
	"github.com/kanocz/lcvpn/netlink"
	"golang.org/x/net/ipv4"
	"golang.org/x/crypto/ssh/terminal"
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
	//BUFFERSIZE = 1500 - 4
	MTU = "1300"
	BUFFERSIZE = 1496
)

type AuthResponse struct{
    EncryptionKey string
    UserID string
    Gateways map[string]*Gateway
}

type Gateway struct {
	Hostname string
	Ip net.IP
	Routes []string
}

func runIP(args ...string) error {
	cmd := exec.Command("/sbin/ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	return err
}


func RoutePacket(ip net.IP, gateways map[string]*Gateway) (net.IP, error) {
	for _, gateway := range gateways {
		for _,route := range gateway.Routes {
			_, route_net,_ := net.ParseCIDR(route)
			//routing_ip, routing_net,_ := net.ParseCIDR(ip)
			if route_net.Contains(ip) {
				return gateway.Ip, nil
			}
		}
	}
	return nil, errors.New("Packet does not belong to a Gateway.")
}


func main() {
	//Parameters
	version := flag.Bool("version", false, "print novpn version")
	client_cert := flag.String("cert","client.crt","client certificate (.crt)")
	client_key := flag.String("key","client.key","client certificate key (.key)")
	ca_cert := flag.String("ca","ca.crt","CA certificate (.crt)")
	ace_hostname := flag.String("acehostname","localhost","ACE hostname/IP")
	ace_port := flag.Int("aceport",443,"ACE port (default: 443)")
	flag.Parse()
	authParams := AuthResponse{}
	//Version
	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}
	//Print out variables
	log.Println("Using client certificate:",*client_cert)
	log.Println("Using client certificate key:",*client_key)
	log.Println("Using CA certificate:",*ca_cert)
	//##############################################################Call ACE Server
	//Load CA certiifcate
	caCert, err := ioutil.ReadFile(*ca_cert)
	if nil != err{
		log.Fatal("Cannot read CA certificate:",err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	//Load client cert/key pair
	cert, err := tls.LoadX509KeyPair(*client_cert,*client_key)
	if nil != err{
		log.Fatal("Cannot read Client Certificate:",err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	//Make POST request to ACE server
	fmt.Print("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if nil != err {
        log.Fatal("Error reading password:",err)
    }
	u := url.Values{}
	u.Set("password",string(bytePassword))
	resp, err := client.PostForm("https://"+*ace_hostname+":"+strconv.Itoa(*ace_port)+"/login",u)
	if nil != err {
		log.Fatal("Could not contact ACE server:",err)
	} else {
		switch resp.StatusCode {
		case 403:
			log.Fatal("ACE Server replied: Invalid credentials.")
		case 201:
			log.Println("ACE Server replied: Authentication successful.")
			json.NewDecoder(resp.Body).Decode(&authParams)
			fmt.Println("Encryption Key:",authParams.EncryptionKey)
			fmt.Println("User ID:",authParams.UserID)
		default:
			log.Fatal("Ace Server replied: Unknown error ->",resp.Status)
		}
	}
	//#######################################Client authenticated
	//Create tunnel
	iface, err := water.NewTUN("")
	if nil != err {
		log.Fatal("Could not create tunnel interface:",err)
	} else {
		log.Println("Interface created:",iface.Name())
	}
	err = runIP("link","set","dev",iface.Name(),"mtu",MTU)
	err = runIP("addr","add","169.254.255.255/32","dev",iface.Name())
	err = runIP("link","set","dev",iface.Name(),"up")
	if nil != err {
		log.Fatal("Could not configure tunnel:",err)
	} else {
		log.Println("Tunnel configured successfully.")
	}
	//Get Gateways hostnames and Routes
	for k, v := range authParams.Gateways {
		ip, err := net.LookupIP(v.Hostname)
		if nil != err {
			log.Println("Could not resolve hostname",v.Hostname)
		} else {
			v.Ip = ip[0]
			log.Println("Gateway's name:",k,"Address:",v.Hostname,"(",v.Ip,")")
			log.Println("Routes:")
			for _,route := range v.Routes {
				//Add route to routing table
				err := netlink.AddRoute(route, "", "", iface.Name())
				if nil != err {
					log.Println("Could not add route",route)
				} else {
					log.Println("Route",route,"added successfully.")
				}
			}
		}
	}
	packet := make([]byte, BUFFERSIZE)
	log.Println("Starting interface main loop.")
	for {
		plen, err := iface.Read(packet)
		if nil != err {
			log.Println("Error reading packet:",err)
			break
		} else {
			log.Println("Received packet with",plen,"bytes on interface.")
		}
		header,_ := ipv4.ParseHeader(packet[:plen])
		//Only IPv4
		if header.Version != 4 {
			continue
		}
		log.Println("IP Header:",header)
		routing_gateway, err := RoutePacket(header.Dst,authParams.Gateways)
		if nil != err {
			log.Println(err)
			continue
		} else {
			//Route the packet
			conn, err := net.Dial("udp",fmt.Sprintf("%s:444",routing_gateway))
			if nil != err {
				log.Println("Unable to dial gateway",routing_gateway)
				continue
			}
			//Append UserID first, then the packet
			dst := make([]byte, hex.DecodedLen(len([]byte(authParams.UserID))))
			hex.Decode(dst,[]byte(authParams.UserID))
			conn.Write(append(dst,packet[:plen]...))
		}
	}
	log.Println("Exit interface main loop.")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	log.Println(text)
}
