package services

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/routeros.v2"
)

const (
	routerOsKeyCreationRetries = 3
	routerOsPoolSize           = 5
	clientLifeTime             = 1 * time.Minute
	routerOsApiDialTimeout     = 20 * time.Second
	interfaceResolutionPeriod  = 1 * time.Hour
)

type RouterOSWireguardPeer struct {
	PublicKey              string      `mapstructure:"public-key"`
	EndpointPort           int         `mapstructure:"endpoint-port"`
	CurrentEndpointAddress string      `mapstructure:"current-endpoint-address"`
	AllowedAddress         []net.IPNet `mapstructure:"allowed-address"`
	Tx                     int         `mapstructure:"tx"`
	Comment                string      `mapstructure:"comment"`
	Id                     string      `mapstructure:".id"`
	Interface              string      `mapstructure:"interface"`
	EndpointAddress        string      `mapstructure:"endpoint-address"`
	CurrentEndpointPort    int         `mapstructure:"current-endpoint-port"`
	Rx                     int         `mapstructure:"rx"`
	Disabled               bool        `mapstructure:"disabled"`
}

type RouterOSWireguardInterface struct {
	Id         string `mapstructure:".id"`
	Name       string `mapstructure:"name"`
	Mtu        int    `mapstructure:"mtu"`
	ListenPort uint   `mapstructure:"listen-port"`
	PublicKey  string `mapstructure:"public-key"`
	Running    bool   `mapstructure:"running"`
	Disabled   bool   `mapstructure:"disabled"`
}

type RouterOSIpAddress struct {
	Id              string        `mapstructure:".id"`
	Address         utils.IPnMask `mapstructure:"address"`
	Network         net.IP        `mapstructure:"network"` // Network base address, not an IP+Netmask
	Interface       string        `mapstructure:"interface"`
	ActualInterface string        `mapstructure:"actual-interface"`
	Disabled        bool          `mapstructure:"disabled"`
	Dynamic         bool          `mapstructure:"dynamic"`
	Invalid         bool          `mapstructure:"invalid"`
}

type RouterOSIpCloud struct {
	DdnsEnabled        bool   `mapstructure:"ddns-enabled"`
	PublicAddress      net.IP `mapstructure:"public-address"`
	PublicAddressIpv6  net.IP `mapstructure:"public-address-ipv6"`
	DdnsUpdateInterval *uint  `mapstructure:"ddns-update-interval"`
	UpdateTime         bool   `mapstructure:"update-time"`
	DnsName            string `mapstructure:"dns-name"`
	Status             string `mapstructure:"status"`
}

type RouterOSRawApiClient interface {
	RunArgs(args ...string) (*routeros.Reply, error)
	Close()
}

type RouterOSRawApiClientImpl struct {
	client *routeros.Client
}

func (c *RouterOSRawApiClientImpl) RunArgs(args ...string) (*routeros.Reply, error) {
	return c.client.RunArgs(args)
}

func (c *RouterOSRawApiClientImpl) Close() {
	c.client.Close()
}

func NewRouterOSRawApiClient(config *config.RouterOSProviderConfig) (*RouterOSRawApiClientImpl, error) {
	rosClient, err := routeros.DialTimeout(
		fmt.Sprintf("%s:%d", config.Host, config.Port),
		config.Username,
		config.Password,
		routerOsApiDialTimeout,
	)
	if err != nil {
		return nil, err
	}

	return &RouterOSRawApiClientImpl{
		client: rosClient,
	}, nil
}

func RouterOsRawApiClientFactory(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error) {
	return NewRouterOSRawApiClient(config)
}

func routerOsRawApiDecode(input, output interface{}) error {
	configuration := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook:       buildRosApiDecodeHook(),
	}

	decoder, err := mapstructure.NewDecoder(configuration)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
}

func buildRosApiDecodeHook() mapstructure.DecodeHookFunc {
	return mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToIPHookFunc(),
		mapstructure.StringToIPNetHookFunc(),
		utils.StringToIPnMaskHookFunc(),
		utils.CustomNullablePtrHookFunc("none"),
		mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToSliceHookFunc(","),
			utils.StringToIPnMaskHookFunc(),
			mapstructure.StringToIPNetHookFunc(),
			mapstructure.StringToIPHookFunc(),
			utils.CustomNullablePtrHookFunc("none"),
		),
	)
}

type ROSClientPoolEntry struct {
	client       RouterOSRawApiClient
	inUse        bool
	cleanUpTimer *time.Timer
	ownerPool    *ROSClientPool
}

func NewROSClientPoolEntry(ownerPool *ROSClientPool) (*ROSClientPoolEntry, error) {
	client, err := ownerPool.clientFactory(ownerPool.config)
	if err != nil {
		return nil, err
	}

	entry := &ROSClientPoolEntry{
		client:    client,
		inUse:     false,
		ownerPool: ownerPool,
	}

	entry.cleanUpTimer = time.AfterFunc(clientLifeTime, func() { ownerPool.deleteEntry(entry) })

	return entry, nil
}

type ROSClientPool struct {
	config        *config.RouterOSProviderConfig
	maxClients    int
	clients       map[RouterOSRawApiClient]*ROSClientPoolEntry
	mutex         sync.Mutex
	clientFactory func(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error)
}

func NewROSClientPool(
	config *config.RouterOSProviderConfig,
	clientFactory func(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error),
) *ROSClientPool {

	return &ROSClientPool{
		config:        config,
		maxClients:    routerOsPoolSize,
		clientFactory: clientFactory,
		clients:       make(map[RouterOSRawApiClient]*ROSClientPoolEntry, 0),
	}
}

func (p *ROSClientPool) getCreateClient() (RouterOSRawApiClient, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, clientEntry := range p.clients {
		if !clientEntry.inUse {
			clientEntry.inUse = true
			return clientEntry.client, nil
		}
	}

	if len(p.clients) < p.maxClients {
		entry, err := NewROSClientPoolEntry(p)
		if err != nil {
			return nil, err
		}
		p.clients[entry.client] = entry
		return entry.client, nil
	}

	return nil, nil
}

func (p *ROSClientPool) releaseClient(client RouterOSRawApiClient) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, entry := range p.clients {
		if entry.client == client {
			entry.inUse = false
			return
		}
	}
	panic("client to be released not found")
}

func (p *ROSClientPool) deleteEntry(entry *ROSClientPoolEntry) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !entry.inUse {
		entry.cleanUpTimer.Stop()
		entry.client.Close()
		delete(entry.ownerPool.clients, entry.client)
	} else {
		entry.cleanUpTimer.Reset(clientLifeTime)
	}
}

func (p *ROSClientPool) RunOnPool(cb func(rawClient RouterOSRawApiClient) (*routeros.Reply, error)) (*routeros.Reply, error) {
	client, err := p.getCreateClient()
	if err != nil {
		return nil, err
	}
	defer p.releaseClient(client)
	return cb(client)
}

func (p *ROSClientPool) RunOnPoolNoResp(cb func(rawClient RouterOSRawApiClient) error) error {
	_, err := p.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
		return nil, cb(rawClient)
	})
	return err
}

type ROSWireguardRouterProvider struct {
	name                     string
	config                   *config.RouterOSProviderConfig
	clientPool               *ROSClientPool
	interfaceResolutionCbs   []WireguardInterfaceResolutionFunc
	interfaceResolutionTimer *time.Ticker
}

func NewROSWireguardRouterProvider(
	name string,
	config *config.RouterOSProviderConfig,
	clientFactory func(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error),
) *ROSWireguardRouterProvider {

	return &ROSWireguardRouterProvider{
		name:                   name,
		config:                 config,
		clientPool:             NewROSClientPool(config, clientFactory),
		interfaceResolutionCbs: make([]WireguardInterfaceResolutionFunc, 0),
	}
}

func (p *ROSWireguardRouterProvider) SubscribeTunnelInterfaceResolution(cb WireguardInterfaceResolutionFunc) {
	p.interfaceResolutionCbs = append(p.interfaceResolutionCbs, cb)
}

func (p *ROSWireguardRouterProvider) TryDeletePeers(_ *models.WireguardTunnelInfo, publicKeys ...string) (uint, error) {
	var cnt uint
	var err error
	err = p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		cnt, err = tryDeletePeers(rawClient, publicKeys...)
		return err
	})
	return cnt, err
}

func (p *ROSWireguardRouterProvider) GetInterfaceIp(name string) (net.IP, *net.IPNet, error) {
	reply, err := p.clientPool.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
		return rawClient.RunArgs("/ip/address/print", fmt.Sprintf("?interface=%s", name))
	})

	if err != nil {
		return nil, nil, err
	}
	if len(reply.Re) != 1 {
		return nil, nil, fmt.Errorf("cannot find interface %s", name)
	}

	var rosIpAddress RouterOSIpAddress
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosIpAddress); err != nil {
		return nil, nil, err
	}

	netIp, netMask := utils.AlignNetMask(rosIpAddress.Network, rosIpAddress.Address.Mask)
	return rosIpAddress.Address.IP, &net.IPNet{IP: netIp, Mask: netMask}, nil
}

func (p *ROSWireguardRouterProvider) OnBoot() error {
	if err := p.clientPool.RunOnPoolNoResp(p.runInterfaceResolution); err != nil {
		logging.Logger.Errorw(
			"error running routeros interface resolution on boot",
			"error", err.Error(),
		)
		return err
	}

	if p.interfaceResolutionTimer == nil {
		p.interfaceResolutionTimer = time.NewTicker(interfaceResolutionPeriod)

		// Launch DNS resolution as a routine
		go p.routerOsInterfaceResolutionRoutine()
	}

	return nil
}

func (p *ROSWireguardRouterProvider) CreatePeer(
	description, psk string,
	tunnelInfo *models.WireguardTunnelInfo,
	profileInfo *models.WireguardTunnelProfileInfo,
	peerAddress net.IP,
) (*WireguardPeerKeyPair, error) {
	for index := 0; index < routerOsKeyCreationRetries; index++ {

		kp, err := buildWireguardApiPair()
		if err != nil {
			return nil, err
		}

		_, err = p.clientPool.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
			return addPeerToInterface(rawClient, tunnelInfo.Interface, kp.PublicKey, psk, description,
				profileInfo.Ranges, peerAddress)
		})

		if err != nil && routerOSResourceAlreadyExistsError(routerOSRetrieveApiErrorMessage(err)) {
			// Key already exists
			continue
		} else if err != nil {
			return nil, err
		}
		return kp, nil
	}

	return nil, fmt.Errorf("cannot create peer")
}

func (p *ROSWireguardRouterProvider) Close() {
	for _, entry := range p.clientPool.clients {
		p.clientPool.deleteEntry(entry)
	}
	if p.interfaceResolutionCbs != nil {
		p.interfaceResolutionTimer.Stop()
	}
}

func (p *ROSWireguardRouterProvider) routerOsInterfaceResolutionRoutine() {
	for {
		select {
		case _, ok := <-p.interfaceResolutionTimer.C:
			if !ok {
				logging.Logger.Debug("Exiting the routerOsInterfaceResolutionRoutine")
				return
			}
		}
		if err := p.clientPool.RunOnPoolNoResp(p.runInterfaceResolution); err != nil {
			logging.Logger.Errorw(
				"error running routeros interface resolution process",
				"error", err.Error(),
			)
		}
	}
}

func (p *ROSWireguardRouterProvider) runInterfaceResolution(client RouterOSRawApiClient) error {
	// If no subscriptions just skip
	if len(p.interfaceResolutionCbs) == 0 {
		return nil
	}

	var endpointHost string

	endpointHost, err := p.getTunnelInterfaceHost(client)
	if err != nil {
		return err
	}

	if len(endpointHost) == 0 {
		return errors.New("runInterfaceResolution error getting tunnel interface host")
	}

	interfaceResolutions := make([]WireguardInterfaceResolutionData, 0)
	for _, tun := range p.config.WireguardTunnels {
		iface, err := getWireguardInterface(client, tun.Interface)
		if err != nil {
			logging.Logger.Errorw(
				"error getting tunnel interface data",
				"interface", tun.Interface,
				"error", err.Error(),
			)
			continue
		}

		resolutionData := WireguardInterfaceResolutionData{
			Endpoint:  fmt.Sprintf("%s:%d", endpointHost, iface.ListenPort),
			PublicKey: iface.PublicKey,
			Name:      iface.Name,
		}
		interfaceResolutions = append(interfaceResolutions, resolutionData)
	}

	for _, cb := range p.interfaceResolutionCbs {
		cb(p.name, interfaceResolutions)
	}

	return nil
}

func (p *ROSWireguardRouterProvider) getTunnelInterfaceHost(client RouterOSRawApiClient) (string, error) {
	// If host not configured just try to get it from MK Cloud
	if len(p.config.TunnelEndpoint) == 0 && len(p.config.TunnelEndpointInterface) == 0 {
		ipCloud, err := getIpCloudData(client)
		if err != nil {
			logging.Logger.Error("runInterfaceResolution failed to resolve IP Cloud data")
			return "", err
		} else if len(ipCloud.DnsName) != 0 {
			return ipCloud.DnsName, nil
		} else if !ipCloud.PublicAddress.IsUnspecified() {
			return ipCloud.PublicAddress.String(), nil
		} else {
			return "", errors.New("cannot resolve routeros interface IP/host")
		}
	} else if len(p.config.TunnelEndpoint) != 0 {
		return p.config.TunnelEndpoint, nil
	} else {
		reply, err := client.RunArgs("/ip/address/print", fmt.Sprintf("?interface=%s", p.config.TunnelEndpointInterface))
		if err != nil {
			logging.Logger.Errorw(
				"runInterfaceResolution failed to resolve IP of interface",
				"interface", p.config.TunnelEndpointInterface,
				"error", err.Error())
			return "", err
		} else if len(reply.Re) != 1 {
			return "", fmt.Errorf("cannot find a single interface %s IP", p.config.TunnelEndpointInterface)
		}

		var rosIpAddress RouterOSIpAddress
		if err := routerOsRawApiDecode(reply.Re[0].Map, &rosIpAddress); err != nil {
			return "", err
		}
		return rosIpAddress.Address.IP.String(), nil
	}
}

func getIpCloudData(client RouterOSRawApiClient) (*RouterOSIpCloud, error) {
	const command string = "/ip/cloud/print"
	reply, err := client.RunArgs(command)
	if err != nil {
		return nil, fmt.Errorf("getIpCloudData failed at running %s %s ", command, err.Error())
	}

	if len(reply.Re) != 1 {
		return nil, errors.New("getIpCloudData failed with unexpected return value")
	}

	var rosIpCloud RouterOSIpCloud
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosIpCloud); err != nil {
		return nil, errors.New("getIpCloudData failed to decode response data")
	}

	return &rosIpCloud, nil
}

func getWireguardInterface(client RouterOSRawApiClient, name string) (*RouterOSWireguardInterface, error) {
	reply, err := client.RunArgs("/interface/wireguard/print", fmt.Sprintf("?name=%s", name))

	if err != nil {
		return nil, errors.New("getWireguardInterface failed at running ")
	}

	if len(reply.Re) != 1 {
		return nil, errors.New("getWireguardInterface failed with unexpected return value")
	}

	var rosInterface RouterOSWireguardInterface
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosInterface); err != nil {
		return nil, errors.New("getWireguardInterface failed to decode response data")
	}

	return &rosInterface, nil
}

func addPeerToInterface(
	client RouterOSRawApiClient,
	iface, pubKey, psk, description string,
	networks []net.IPNet,
	peerAddress net.IP,
) (*routeros.Reply, error) {
	command := []string{
		"/interface/wireguard/peers/add",
		fmt.Sprintf("=interface=%s", iface),
		fmt.Sprintf("=public-key=%s", pubKey),
	}

	if len(psk) != 0 {
		command = append(command, fmt.Sprintf("=preshared-key=%s", psk))
	}

	comment := "@@Tunnel Provisioner Managed"
	if len(description) != 0 {
		comment = comment + ": " + comment
	}

	command = append(command, fmt.Sprintf("=comment=%s", comment))

	networksString := fmt.Sprintf("%s/32", peerAddress.String())
	for _, network := range networks {
		networksString = networksString + fmt.Sprintf(",%s", network.String())
	}
	command = append(command, fmt.Sprintf("=allowed-address=%s", strings.Trim(networksString, ",")))

	logging.Logger.Debugw("ROS add peer to be run",
		"command", utils.SanitizeStringWithValues(strings.Join(command, " "), psk, pubKey),
	)

	return client.RunArgs(command...)
}

func tryDeletePeers(client RouterOSRawApiClient, pubKeys ...string) (uint, error) {
	commandQuery := []string{"/interface/wireguard/peers/print"}

	logging.Logger.Debugw(
		"ROS find by pubkey query to be run",
		"command", strings.Join(commandQuery, " "),
	)

	reply, err := client.RunArgs(commandQuery...)
	if err != nil {
		return 0, err
	}

	remotePeerIds := make(map[string]string, 0)
	for _, re := range reply.Re {
		var peer RouterOSWireguardPeer
		if err := routerOsRawApiDecode(re.Map, &peer); err != nil {
			logging.Logger.Errorw("error decoding wireguard peer id to be removed")
		} else if peer.Id == "" && len(peer.PublicKey) == 0 {
			logging.Logger.Errorw("wireguard peer id to be mass removed is empty. Peer will be skipped")
		} else {
			remotePeerIds[peer.PublicKey] = peer.Id
		}
	}

	var toDeletePeersIds []string
	for _, toRemoveKey := range pubKeys {
		if id, ok := remotePeerIds[toRemoveKey]; ok {
			toDeletePeersIds = append(toDeletePeersIds, id)
		}
	}

	if len(toDeletePeersIds) != 0 {
		commandDelete := []string{
			"/interface/wireguard/peers/remove",
			fmt.Sprintf("=.id=%s", strings.Trim(strings.Join(toDeletePeersIds, ","), ",")),
		}
		logging.Logger.Debugw(
			"ROS delete to be run",
			"command", strings.Join(commandDelete, " "),
		)

		if _, err := client.RunArgs(commandDelete...); err != nil {
			return 0, err
		}
		return uint(len(toDeletePeersIds)), nil
	}

	return 0, err
}

func routerOSRetrieveApiErrorMessage(error error) string {
	val, ok := error.(*routeros.DeviceError)
	if ok {
		if errMsg, ok := val.Sentence.Map["message"]; ok {
			return errMsg
		}
	}
	return ""
}

func routerOSResourceAlreadyExistsError(errorMsg string) bool {
	return strings.Contains(errorMsg, "entry already exists")
}
