package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"crypto/x509"
	"crypto/tls"
	"net/http"
	"net/url"
	"strconv"
	"encoding/json"

	"github.com/matishsiao/go_reuseport"
	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	// AppVersion contains current application version for -version command flag
	AppVersion = "0.0.1"
)

const (
	// I use TUN interface, so only plain IP packet,
	// no ethernet header + mtu is set to 1300

	// BUFFERSIZE is size of buffer to receive packets
	// (little bit bigger than maximum)
	//BUFFERSIZE = 1518 - 32
	BUFFERSIZE = 1486
)

type AuthResponse struct{
    EncryptionKey string
    UserID string

    Remote map[string]*struct {
		GwIP string
		Routes []string
	}
}

func rcvrThread(proto string, port int, iface *water.Interface) {
	conn, err := reuseport.NewReusableUDPPortConn(proto, fmt.Sprintf(":%v", port))
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	encrypted := make([]byte, BUFFERSIZE)
	var decrypted IPPacket = make([]byte, BUFFERSIZE)

	for {
		n, _, err := conn.ReadFrom(encrypted)

		if err != nil {
			log.Println("Error: ", err)
			continue
		}

		// ReadFromUDP can return 0 bytes on timeout
		if 0 == n {
			continue
		}

		conf := config.Load().(VPNState)

		if !conf.Main.main.CheckSize(n) {
			log.Println("invalid packet size ", n)
			continue
		}

		size, mainErr := DecryptV4Chk(conf.Main.main, encrypted[:n], decrypted)
		if nil != mainErr {
			if nil != conf.Main.alt {
				size, err = DecryptV4Chk(conf.Main.alt, encrypted[:n], decrypted)
				if nil != err {
					log.Println("Corrupted package: ", mainErr, " / ", err)
					continue
				}
			} else {
				log.Println("Corrupted package: ", mainErr)
				continue
			}
		}

		n, err = iface.Write(decrypted[:size])
		if nil != err {
			log.Println("Error writing to local interface: ", err)
		} else if n != size {
			log.Println("Partial package written to local interface")
		}
	}
}

func sndrThread(conn *net.UDPConn, iface *water.Interface) {
	// first time fill with random numbers
	ivbuf := make([]byte, config.Load().(VPNState).Main.main.IVLen())
	if _, err := io.ReadFull(rand.Reader, ivbuf); err != nil {
		log.Fatalln("Unable to get rand data:", err)
	}

	var packet IPPacket = make([]byte, BUFFERSIZE)
	var encrypted = make([]byte, BUFFERSIZE)

	for {
		plen, err := iface.Read(packet[:MTU])
		if err != nil {
			break
		}

		if 4 != packet.IPver() {
			header, _ := ipv4.ParseHeader(packet)
			log.Printf("Non IPv4 packet [%+v]\n", header)
			continue
		}

		// each time get pointer to (probably) new config
		c := config.Load().(VPNState)

		//This is the inner Dst IP, this packet will be encrypted
		dst := packet.Dst()

		//Addr will be the public IP, should be the Gateway's IP
		addr, ok := c.remotes[dst]

		// very ugly and useful only for a limited numbers of routes!
		
		ip := packet.DstV4()
		for n, s := range c.routes {
			if n.Contains(ip) {
				addr = s
				ok = true
				break
			}
		}

		// new len contatins also 2byte original size
		clen := c.Main.main.AdjustInputSize(plen)

		if clen+c.Main.main.OutputAdd() > len(packet) {
			log.Println("clen + data > len(package)", clen, len(packet))
			continue
		}

		tsize := c.Main.main.Encrypt(packet[:clen], encrypted, ivbuf)

		if ok {
			n, err := conn.WriteToUDP(encrypted[:tsize], addr)
			if nil != err {
				log.Println("Error sending package:", err)
			}
			if n != tsize {
				log.Println("Only ", n, " bytes of ", tsize, " sent")
			}
		} 
	} 
}

func main() {
	//Parameters
	version := flag.Bool("version", false, "print lcvpn version")
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

	//Start SSL agent
	routeReload := make(chan bool, 1)

	var newConfig VPNState

	newConfig.Main.Port = 444
	newConfig.Main.Encryption = "aescbc"
	newConfig.Main.MainKey = authParams.EncryptionKey
	newEFunc := newAesCbc
	newConfig.Main.main, err = newEFunc(newConfig.Main.MainKey)
	if nil != err {
		log.Fatalln("main.mainkey error: %s", err.Error())
	}
	newConfig.routes = map[*net.IPNet]*net.UDPAddr{}
	
	rmtAddr, err := net.ResolveUDPAddr("udp",fmt.Sprintf("%s:%d", "190.190.190.190", 444))
	if nil != err {
		log.Fatalln("Error assigning rmtAddr:",err)
	}
	_, route, err := net.ParseCIDR("10.0.0.0/24")
	if nil != err {
		log.Fatalln("Error parsing route:",err)
	}
	newConfig.routes[route] = rmtAddr
	config.Store(newConfig)

	iface := ifaceSetup("169.254.1.1/32")

	// start routes changes in config monitoring
	routeReload <- true
	go routesThread(iface.Name(), routeReload)

	log.Println("Interface parameters configured")

	// Start listen threads
	for i := 0; i < 4; i++ {
		go rcvrThread("udp4", 444, iface)
	}

	// init udp socket for write

	writeAddr, err := net.ResolveUDPAddr("udp", ":")
	if nil != err {
		log.Fatalln("Unable to get UDP socket:", err)
	}

	writeConn, err := net.ListenUDP("udp", writeAddr)
	if nil != err {
		log.Fatalln("Unable to create UDP socket:", err)
	}

	// Start sender threads

	for i := 0; i < 4; i++ {
		go sndrThread(writeConn, iface)
	}

	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, syscall.SIGTERM)

	<-exitChan

	err = writeConn.Close()
	if nil != err {
		log.Println("Error closing UDP connection: ", err)
	}
}
