package services

import (
	"errors"
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

type WireguardInterfaceInfo struct {
	Name      string
	PublicKey string
	Endpoint  string
	Enabled   bool
}

func (w WireguardInterfaceInfo) String() string {
	return fmt.Sprintf("WireguardInterface[Name=%s, PublicKey=%s, Endpoint=%s, Enabled=%v]",
		w.Name, utils.MasqueradeSensitiveString(w.PublicKey, 5), w.Endpoint, w.Enabled)
}

var ErrProviderInterfaceNotFound = errors.New("provider interface not found")

type WireguardTunnelProvider interface {
	DisposableService
	CreatePeer(description, psk string, tunnelInfo *models.WireguardTunnelInfo, profileInfo *models.WireguardTunnelProfileInfo, peerAddress net.IP) (*WireguardPeerKeyPair, error)
	TryDeletePeers(tunnelInfo *models.WireguardTunnelInfo, publicKey ...string) (uint, error)
	GetInterfaceIp(interfaceName string) (net.IP, *net.IPNet, error)
	GetTunnelInterfaceInfo(interfaceName string) (*WireguardInterfaceInfo, error)
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
		provider.OnClose()
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
