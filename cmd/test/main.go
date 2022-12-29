package main

import (
	"flag"
	"log"
	"strings"

	"gopkg.in/routeros.v2"
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

	// command2 := "/interface/wireguard/peers/add =interface=test-wg =public-key=wglIwKcVpuW6o7QxR0f/gdzJIhEXeWl8yHP70H2vNHU="
	// r, err := c.RunArgs(strings.Split(command2, " "))
	// if err != nil {
	// 	log.Fatal(err)
	// }

	command3 := "/interface/wireguard/peers/print ?interface=test-wg"
	r3, err3 := c.RunArgs(strings.Split(command3, " "))
	if err3 != nil {
		log.Fatal(err3)
	}

	log.Print(r3)
}
