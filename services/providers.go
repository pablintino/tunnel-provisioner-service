package services

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"strings"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
)

type WireguardPeerKeyPair struct {
	PublicKey, PrivateKey string
}

type WireguardTunnelProvider interface {
	CreatePeer(description, psk string, tunnelInfo *models.WireguardTunnelInfo, profileInfo *models.WireguardTunnelProfileInfo, peerAddress net.IP) (*WireguardPeerKeyPair, error)
	DeletePeer(publicKey string, tunnelInfo *models.WireguardTunnelInfo) error
	GetInterfaceIp(name string) (net.IP, *net.IPNet, error)
	Close()
}

func BuilderProvidersMap(config *config.ServiceConfig) map[string]WireguardTunnelProvider {
	providersMap := make(map[string]WireguardTunnelProvider, 0)
	for name, rosProviderConfig := range config.Providers.RouterOS {
		providersMap[name] = NewROSWireguardRouterProvider(&rosProviderConfig, RouterOsRawApiClientFactory)
	}

	return providersMap
}

func CloseProviders(providersMap map[string]WireguardTunnelProvider) {
	for _, provider := range providersMap {
		provider.Close()
	}
}

func sanitizePskPubKeyCommand(command string, toMaskValues ...string) string {
	res := command

	for _, toMask := range toMaskValues {
		if len(toMaskValues) != 0 {
			res = strings.ReplaceAll(command, toMask, "<masked>")
		}
	}
	return res
}

func buildWireguardApiPair() (*WireguardPeerKeyPair, error) {
	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &WireguardPeerKeyPair{
		PublicKey:  peerPrivateKey.PublicKey().String(),
		PrivateKey: peerPrivateKey.String(),
	}, nil
}
