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
	address  = flag.String("address", "10.10.90.1:8728", "RouterOS address and port")
	username = flag.String("username", "pablintino", "User name")
	password = flag.String("password", "5.50GenD3", "Password")
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
	PublicKey              string      `mapstructure:"public-key""`
	EndpointPort           int         `mapstructure:"endpoint-port"`
	CurrentEndpointAddress string      `mapstructure:"current-endpoint-address"`
	AllowedAddress         []net.IPNet `mapstructure:"allowed-address"`
	Tx                     int         `mapstructure:"tx""`
	Comment                string      `mapstructure:"comment"`
	Id                     string      `mapstructure:".id"`
	Interface              string      `mapstructure:"interface"`
	EndpointAddress        string      `mapstructure:"endpoint-address"`
	CurrentEndpointPort    int         `mapstructure:"current-endpoint-port"`
	Rx                     int         `mapstructure:"rx"`
	Disabled               bool        `mapstructure:"disabled"`
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

	command3 := "/interface/wireguard/peers/print ?public-key=qHA5E9OS9FPppF+2qIKsSOIbY3I0bVX9y6e6RZ2QsRc="
	r3, err3 := c.RunArgs(strings.Split(command3, " "))
	if err3 != nil {
		log.Fatal(err3)
	}

	peerId := ""
	var test RouterOSWireguardPeer
	for _, sentence := range r3.Re {

		err2 := WeakDecode(sentence.Map, &test)
		if err2 != nil {
			fmt.Print(err2)
		}

		if id, ok := sentence.Map[".id"]; ok {
			peerId = id
		}
	}

	log.Print(peerId)

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
		DecodeHook:       mapstructure.ComposeDecodeHookFunc(mapstructure.StringToSliceHookFunc(","), mapstructure.StringToIPNetHookFunc()),
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}
