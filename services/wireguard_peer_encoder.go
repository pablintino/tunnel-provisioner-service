package services

import (
	"bufio"
	"bytes"
	"github.com/skip2/go-qrcode"
	"gopkg.in/ini.v1"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"
)

const (
	sectionNameInterface         = "Interface"
	sectionNamePeer              = "Peer"
	filedNameInterfaceAddress    = "Address"
	filedNameInterfacePrivateKey = "PrivateKey"
	filedNameInterfaceDns        = "DNS"
	filedNamePeerPublicKey       = "PublicKey"
	filedNamePeerEndpoint        = "Endpoint"
	filedNamePeerPsk             = "PresharedKey"
	filedNamePeerAllowedIPs      = "AllowedIPs"
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
	interfaceSection, err := wgConfig.NewSection(sectionNameInterface)
	if err != nil {
		return nil, err
	}

	interfaceSection.NewKey(filedNameInterfaceAddress, peer.Ip.String())
	interfaceSection.NewKey(filedNameInterfacePrivateKey, peer.PrivateKey)

	dnss := utils.IPSliceToCommaSeparatedString(tunnelInfo.DNSs)
	if len(dnss) != 0 {
		interfaceSection.NewKey(filedNameInterfaceDns, dnss)
	}

	peerSection, err := wgConfig.NewSection(sectionNamePeer)
	if err != nil {
		return nil, err
	}

	networksString := utils.NetSliceToCommaSeparatedString(profileInfo.Ranges)
	if len(networksString) != 0 {
		peerSection.NewKey(filedNamePeerAllowedIPs, networksString)
	}

	if peer.PreSharedKey != "" {
		peerSection.NewKey(filedNamePeerPsk, peer.PreSharedKey)
	}

	peerSection.NewKey(filedNamePeerPublicKey, tunnelInfo.Interface.PublicKey)
	peerSection.NewKey(filedNamePeerEndpoint, tunnelInfo.Interface.Endpoint)

	var bytesBuffer bytes.Buffer
	foo := bufio.NewWriter(&bytesBuffer)
	wgConfig.WriteTo(foo)
	foo.Flush()

	return qrcode.Encode(string(bytesBuffer.Bytes()), qrcode.Medium, size)
}
