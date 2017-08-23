package main

import (
	"net"
	"sync/atomic"
)

// VPNState represents config mixed with pre-parsed values
type VPNState struct {
	Main struct {
		Port        int
		MainKey     string
		Encryption  string
		UserID		string
		Broadcast   string
		NetCIDR     int
		RecvThreads int
		SendThreads int

		// filled by readConfig
		bcastIP [4]byte
		main    PacketEncrypter
		alt     PacketEncrypter
		local   string
	}
	Remote map[string]*struct {
		ExtIP string
		LocIP string
		Route []string
	}
	// filled by readConfig
	remotes map[[4]byte]*net.UDPAddr
	routes  map[*net.IPNet]*net.UDPAddr
}

var (
	//configfile = flag.String("config", "/etc/lcvpn.conf", "Config file")
	//local      = flag.String("local", "",
	//	"ID from \"remotes\" which idtenify this host [default: autodetect]")
	config atomic.Value
)

func getLocalIPsMap() map[string]bool {
	result := map[string]bool{}

	ipnetlist, err := net.InterfaceAddrs()
	if nil != err {
		return result
	}

	for _, _ipnet := range ipnetlist {
		if ipnet, ok := _ipnet.(*net.IPNet); ok {
			result[ipnet.IP.String()] = true
		}
	}

	return result
}