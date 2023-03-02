package services

import (
	"errors"
	"fmt"
	"net"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"
)

type WireguardPeerKeyPair struct {
	PublicKey, PrivateKey string
}

type WireguardProviderPeer struct {
	Id             string
	PublicKey      string
	AllowedAddress []net.IPNet
	Description    string
	Disabled       bool
	Rx             int
	Tx             int
}

func (w WireguardProviderPeer) String() string {
	return fmt.Sprintf("WireguardProviderPeer[Id=%s, PublicKey=%s, AllowedAddress=%s, Description=%s,"+
		" Disabled=%v, Rx=%d, Tx=%d]", w.Id, utils.MasqueradeSensitiveString(w.PublicKey, 5),
		w.AllowedAddress, w.Description, w.Disabled,
		w.Rx, w.Tx)
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
var ErrProviderPeerNotFound = errors.New("provider peer not found")
var ErrProviderPeerAlreadyExists = errors.New("provider peer already exists")

type WireguardTunnelProvider interface {
	DisposableService
	CreatePeer(
		publicKey, description, psk string,
		tunnelInfo *models.WireguardTunnelInfo,
		profileInfo *models.WireguardTunnelProfileInfo,
		peerAddress net.IP,
	) (*WireguardProviderPeer, error)
	UpdatePeer(id, pubKey, description, psk string,
		tunnelInfo *models.WireguardTunnelInfo,
		profileInfo *models.WireguardTunnelProfileInfo,
		peerAddress net.IP) error
	GetPeerByPublicKey(publicKey string, tunnelInfo *models.WireguardTunnelInfo) (*WireguardProviderPeer, error)
	DeletePeerByPublicKey(tunnelInfo *models.WireguardTunnelInfo, publicKey string) error
	GetInterfaceIp(interfaceName string) (net.IP, *net.IPNet, error)
	GetTunnelInterfaceInfo(interfaceName string) (*WireguardInterfaceInfo, error)
}

func BuilderProvidersMap(config *config.Config) map[string]WireguardTunnelProvider {
	providersMap := make(map[string]WireguardTunnelProvider, 0)
	for name, rosProviderConfig := range config.Providers.RouterOS {
		providersMap[name] = NewROSWireguardRouterProvider(name, &rosProviderConfig, RouterOsRawApiClientFactory)
	}

	return providersMap
}
