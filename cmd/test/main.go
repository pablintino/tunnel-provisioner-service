package main

import (
	"flag"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/routeros.v2"
	"log"
	"net"
	"strings"
)

var (
	command  = flag.String("command", "/interface/wireguard/print", "RouterOS command")
	address  = flag.String("address", "routeros-dev1.internal.pablintino.net:8728", "RouterOS address and port")
	username = flag.String("username", "apitest", "User name")
	password = flag.String("password", "test12345", "Password")
	async    = flag.Bool("async", false, "Use async code")
	useTLS   = flag.Bool("tls", false, "Use TLS")
)

func dial() (*routeros.Client, error) {
	if *useTLS {
		return routeros.DialTLS(*address, *username, *password, nil)
	}
	return routeros.Dial(*address, *username, *password)
}

type RouterOSWireguardPeer struct {
	PublicKey              string      `mapstructure:"public-key"`
	EndpointPort           int         `mapstructure:"endpoint-port"`
	CurrentEndpointAddress string      `mapstructure:"current-endpoint-address"`
	AllowedAddress         []net.IPNet `mapstructure:"allowed-address"`
	Tx                     int         `mapstructure:"tx"`
	Comment                string      `mapstructure:"comment"`
	Id                     string      `mapstructure:".id"`
	Interface              string      `mapstructure:"interface"`
	EndpointAddress        string      `mapstructure:"endpoint-address"`
	CurrentEndpointPort    int         `mapstructure:"current-endpoint-port"`
	Rx                     int         `mapstructure:"rx"`
	Disabled               bool        `mapstructure:"disabled"`
}

type RouterOSIpAddress struct {
	Id              string    `mapstructure:".id"`
	Address         net.IPNet `mapstructure:"address"`
	Network         net.IP    `mapstructure:"network"` // Network base address, not an IP+Netmask
	Interface       string    `mapstructure:"interface"`
	ActualInterface string    `mapstructure:"actual-interface"`
	Disabled        bool      `mapstructure:"disabled"`
	Dynamic         bool      `mapstructure:"dynamic"`
	Invalid         bool      `mapstructure:"invalid"`
}

type RouterOSIpCloud struct {
	DdnsEnabled        bool   `mapstructure:"ddns-enabled"`
	PublicAddress      net.IP `mapstructure:"public-address"`
	PublicAddressIpv6  net.IP `mapstructure:"public-address-ipv6"`
	DdnsUpdateInterval int    `mapstructure:"ddns-update-interval"`
	UpdateTime         bool   `mapstructure:"update-time"`
	DnsName            string `mapstructure:"dns-name"`
	Status             string `mapstructure:"status"`
}

type RouterOSWireguardInterface struct {
	Id         string `mapstructure:".id"`
	Name       string `mapstructure:"name"`
	Mtu        int    `mapstructure:"mtu"`
	ListenPort uint   `mapstructure:"listen-port"`
	PublicKey  string `mapstructure:"public-key"`
	Running    bool   `mapstructure:"running"`
	Disabled   bool   `mapstructure:"disabled"`
}

func main() {
	flag.Parse()

	c, err := dial()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if *async {
		c.Async()
	}

	command3 := "/interface/wireguard/peers/print detail"
	r3, err3 := c.RunArgs(strings.Split(command3, " "))
	if err3 != nil {
		log.Fatal(err3)
	}

	var test RouterOSWireguardInterface
	err2 := WeakDecode(r3.Re[0].Map, &test)
	if err2 != nil {
		fmt.Print(err2)
	}
	log.Print(test)

	//command4 := fmt.Sprintf("/interface/wireguard/peers/remove =.id=%s", peerId)
	//r4, err4 := c.RunArgs(strings.Split(command4, " "))
	//if err4 != nil {
	//	log.Fatal(err4)
	//}
	//
	//log.Print(r4)
}

func WeakDecode(input, output interface{}) error {
	config := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToIPHookFunc(),
			mapstructure.StringToIPNetHookFunc(),
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToSliceHookFunc(","),
				mapstructure.StringToIPNetHookFunc(), mapstructure.StringToIPHookFunc(),
			),
		),
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}
