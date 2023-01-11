package services

import (
	"fmt"
	"net"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireguardPeerKeyPair struct {
	PublicKey, PrivateKey string
}

type WireguardInterfaceResolutionData struct {
	Name      string
	PublicKey string
	Dns       string
	Port      uint
}

func (w WireguardInterfaceResolutionData) String() string {
	return fmt.Sprintf("WireguardInterface[Name=%s, PublicKey=%s, Dns=%s, Port=%d]",
		w.Name, utils.MasqueradeSensitiveString(w.PublicKey, 5), w.Dns, w.Port)
}

type WireguardInterfaceResolutionFunc func(provider string, resolutionData []WireguardInterfaceResolutionData)

type WireguardTunnelProvider interface {
	CreatePeer(description, psk string, tunnelInfo *models.WireguardTunnelInfo, profileInfo *models.WireguardTunnelProfileInfo, peerAddress net.IP) (*WireguardPeerKeyPair, error)
	DeletePeer(publicKey string, tunnelInfo *models.WireguardTunnelInfo) error
	DeletePeers(tunnelInfo *models.WireguardTunnelInfo, publicKey ...string) error
	GetInterfaceIp(name string) (net.IP, *net.IPNet, error)
	SubscribeTunnelInterfaceResolution(cb WireguardInterfaceResolutionFunc)
	Close()
}

func BuilderProvidersMap(config *config.ServiceConfig) map[string]WireguardTunnelProvider {
	providersMap := make(map[string]WireguardTunnelProvider, 0)
	for name, rosProviderConfig := range config.Providers.RouterOS {
		providersMap[name] = NewROSWireguardRouterProvider(name, &rosProviderConfig, RouterOsRawApiClientFactory)
	}

	return providersMap
}

func CloseProviders(providersMap map[string]WireguardTunnelProvider) {
	for _, provider := range providersMap {
		provider.Close()
	}
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
