package services

import (
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
)

type WireguardTunnelProvider interface {
	CreateTunnel(description string, psk *string) (*models.WireguardPeerModel, error)
}

type ROSWireguardRouterProvider struct {
	config *config.RouterOSConfig
}

func (p *ROSWireguardRouterProvider) CreateTunnel(description string, psk *string) (*models.WireguardPeerModel, error) {
	//peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	//if err != nil {
	//	return nil, err
	//}

	//peerPubKey := peerPrivateKey.PublicKey().String()
	//peerPrivateKeyStr := peerPrivateKey.String()
	//p.createPeer(peerPrivateKeyStr, peerPubKey, description, psk)
	return nil, nil

}

func (p *ROSWireguardRouterProvider) createPeer(pk, pubKey, description string, psk *string, addresses []string) error {
	return nil
}

func (p *ROSWireguardRouterProvider) getInterfacePubKey(pk, pubKey, description string, psk *string, addresses []string) error {
	return nil
}
