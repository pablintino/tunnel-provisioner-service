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

	if _, err = interfaceSection.NewKey(filedNameInterfaceAddress, peer.Ip.String()); err != nil {
		return nil, err
	}

	if _, err = interfaceSection.NewKey(filedNameInterfacePrivateKey, peer.PrivateKey); err != nil {
		return nil, err
	}

	if len(tunnelInfo.DNSs) != 0 {
		if _, err = interfaceSection.NewKey(filedNameInterfaceDns, utils.IPSliceToCommaSeparatedString(tunnelInfo.DNSs)); err != nil {
			return nil, err
		}
	}

	peerSection, err := wgConfig.NewSection(sectionNamePeer)
	if err != nil {
		return nil, err
	}

	if len(profileInfo.Ranges) != 0 {
		if _, err = peerSection.NewKey(filedNamePeerAllowedIPs, utils.NetSliceToCommaSeparatedString(profileInfo.Ranges)); err != nil {
			return nil, err
		}
	}

	if peer.PreSharedKey != "" {
		if _, err = peerSection.NewKey(filedNamePeerPsk, peer.PreSharedKey); err != nil {
			return nil, err
		}
	}

	if _, err := peerSection.NewKey(filedNamePeerPublicKey, tunnelInfo.Interface.PublicKey); err != nil {
		return nil, err
	}
	_, err = peerSection.NewKey(filedNamePeerEndpoint, tunnelInfo.Interface.Endpoint)
	if err != nil {
		return nil, err
	}
	var bytesBuffer bytes.Buffer
	foo := bufio.NewWriter(&bytesBuffer)
	if _, err := wgConfig.WriteTo(foo); err != nil {
		return nil, err
	}
	foo.Flush()

	return qrcode.Encode(bytesBuffer.String(), qrcode.Medium, size)
}
