package services

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/skip2/go-qrcode"
	"gopkg.in/ini.v1"
	"strings"
	"tunnel-provisioner-service/models"
)

type WireguardQrEncoder interface {
	Encode(model *models.WireguardPeerModel,
		tunnelInfo *models.WireguardTunnelInfo,
		profileInfo *models.WireguardTunnelProfileInfo,
		size int) ([]byte, error)
}

type WireguardQrEncoderImpl struct {
}

func NewWireguardQrEncoder() *WireguardQrEncoderImpl {
	return &WireguardQrEncoderImpl{}
}

func (e *WireguardQrEncoderImpl) Encode(
	peer *models.WireguardPeerModel,
	tunnelInfo *models.WireguardTunnelInfo,
	profileInfo *models.WireguardTunnelProfileInfo,
	size int) ([]byte, error) {
	wgConfig := ini.Empty()
	interfaceSection, err := wgConfig.NewSection("Interface")
	if err != nil {
		return nil, err
	}

	interfaceSection.NewKey("Address", peer.Ip.String())
	interfaceSection.NewKey("PrivateKey", peer.PrivateKey)

	if len(tunnelInfo.DNSs) != 0 {
		nameServers := ""
		for _, dns := range tunnelInfo.DNSs {
			nameServers = nameServers + fmt.Sprintf(",%s", dns.String())
		}
		interfaceSection.NewKey("DNS", strings.Trim(nameServers, ","))
	}

	peerSection, err := wgConfig.NewSection("Peer")
	if err != nil {
		return nil, err
	}

	networksString := ""
	for _, network := range profileInfo.Ranges {
		networksString = networksString + fmt.Sprintf(",%s", network.String())
	}
	peerSection.NewKey("AllowedIPs", strings.Trim(networksString, ","))

	if peer.PreSharedKey != "" {
		peerSection.NewKey("PresharedKey", peer.PreSharedKey)
	}

	peerSection.NewKey("PublicKey", tunnelInfo.Interface.PublicKey)
	peerSection.NewKey("Endpoint", tunnelInfo.Interface.Endpoint)

	var bytesBuffer bytes.Buffer
	foo := bufio.NewWriter(&bytesBuffer)
	wgConfig.WriteTo(foo)
	foo.Flush()

	return qrcode.Encode(string(bytesBuffer.Bytes()), qrcode.Medium, size)
}
