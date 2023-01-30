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
	routerOsPoolSize                = 5
	clientLifeTime                  = 5 * time.Minute
	routerOsApiDialTimeout          = 15 * time.Second
	routerOsCommentPrefix           = "@@Tunnel Provisioner Managed"
	routerOsResponseMessageExists   = "entry already exists"
	routerOsResponseMessageNotFound = "no such item"
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

func (p *RouterOSWireguardPeer) toProviderPeer() *WireguardProviderPeer {
	return &WireguardProviderPeer{
		Id:             p.Id,
		PublicKey:      p.PublicKey,
		AllowedAddress: p.AllowedAddress,
		Disabled:       p.Disabled,
		Description:    strings.TrimLeft(strings.ReplaceAll(p.Comment, routerOsCommentPrefix, ""), ": "),
		Rx:             p.Rx,
		Tx:             p.Tx,
	}
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

func (p *ROSClientPool) RunOnPoolIgnoreResp(cb func(rawClient RouterOSRawApiClient) (*routeros.Reply, error)) error {
	_, err := p.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
		_, err := cb(rawClient)
		return nil, err
	})
	return err
}

type ROSWireguardRouterProvider struct {
	name                     string
	config                   *config.RouterOSProviderConfig
	clientPool               *ROSClientPool
	interfaceResolutionTimer *time.Ticker
}

func NewROSWireguardRouterProvider(
	name string,
	config *config.RouterOSProviderConfig,
	clientFactory func(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error),
) *ROSWireguardRouterProvider {

	return &ROSWireguardRouterProvider{
		name:       name,
		config:     config,
		clientPool: NewROSClientPool(config, clientFactory),
	}
}

func (p *ROSWireguardRouterProvider) UpdatePeer(
	id, pubKey, description, psk string,
	tunnelInfo *models.WireguardTunnelInfo,
	profileInfo *models.WireguardTunnelProfileInfo,
	peerAddress net.IP,
) error {
	return p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		_, err := updatePeer(rawClient, id, tunnelInfo.Interface.Name, pubKey, psk, description, profileInfo.Ranges, peerAddress)
		if err != nil && routerOSResourceAlreadyExistsError(routerOSRetrieveApiErrorMessage(err)) {
			return ErrProviderPeerAlreadyExists
		} else if err != nil && routerOSResourceNotFoundError(routerOSRetrieveApiErrorMessage(err)) {
			return ErrProviderPeerNotFound
		}
		return err
	})
}

func (p *ROSWireguardRouterProvider) DeletePeerByPublicKey(tunnelInfo *models.WireguardTunnelInfo, publicKey string) error {
	return p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		return deletePeersByPublicKeys(rawClient, publicKey, tunnelInfo)
	})
}

func (p *ROSWireguardRouterProvider) GetPeerByPublicKey(publicKey string, tunnelInfo *models.WireguardTunnelInfo) (*WireguardProviderPeer, error) {
	var peer *WireguardProviderPeer
	err := p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		var commandErr error
		peer, commandErr = getPeerByPublicKey(rawClient, publicKey, tunnelInfo)
		return commandErr
	})
	return peer, err
}

func (p *ROSWireguardRouterProvider) GetInterfaceIp(name string) (net.IP, *net.IPNet, error) {
	var ipAddress *RouterOSIpAddress
	err := p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		var commandErr error
		ipAddress, commandErr = getInterfaceIpAddress(rawClient, name)
		return commandErr
	})
	if err != nil {
		return nil, nil, err
	}

	netIp, netMask := utils.AlignNetMask(ipAddress.Network, ipAddress.Address.Mask)
	return ipAddress.Address.IP, &net.IPNet{IP: netIp, Mask: netMask}, nil
}

func (p *ROSWireguardRouterProvider) GetTunnelInterfaceInfo(interfaceName string) (*WireguardInterfaceInfo, error) {
	var resolutionData *WireguardInterfaceInfo
	err := p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		var commandErr error
		resolutionData, commandErr = p.getWireguardInterfaceResolutionData(rawClient, interfaceName)
		return commandErr
	})

	return resolutionData, err
}

func (p *ROSWireguardRouterProvider) CreatePeer(
	publicKey, description, psk string,
	tunnelInfo *models.WireguardTunnelInfo,
	profileInfo *models.WireguardTunnelProfileInfo,
	peerAddress net.IP) (*WireguardProviderPeer, error) {
	var peer *WireguardProviderPeer
	err := p.clientPool.RunOnPoolNoResp(func(rawClient RouterOSRawApiClient) error {
		var commandErr error
		peer, commandErr = addPeerToInterface(rawClient, tunnelInfo.Interface.Name, publicKey, psk, description,
			profileInfo.Ranges, peerAddress)
		if commandErr != nil && routerOSResourceAlreadyExistsError(routerOSRetrieveApiErrorMessage(commandErr)) {
			return ErrProviderPeerAlreadyExists
		}
		return commandErr
	})
	return peer, err

}

func (p *ROSWireguardRouterProvider) OnClose() {
	for _, entry := range p.clientPool.clients {
		p.clientPool.deleteEntry(entry)
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
		return nil, ErrProviderInterfaceNotFound
	}

	var rosInterface RouterOSWireguardInterface
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosInterface); err != nil {
		return nil, errors.New("getWireguardInterface failed to decode response data")
	}

	return &rosInterface, nil
}

func (p *ROSWireguardRouterProvider) getWireguardInterfaceResolutionData(rawClient RouterOSRawApiClient, interfaceName string) (*WireguardInterfaceInfo, error) {

	wireguardInterface, err := getWireguardInterface(rawClient, interfaceName)
	if err != nil {
		return nil, err
	}

	endpointHost, err := p.getTunnelInterfaceHost(rawClient)
	if err != nil {
		return nil, err
	}

	resolutionData := WireguardInterfaceInfo{
		Endpoint:  fmt.Sprintf("%s:%d", endpointHost, wireguardInterface.ListenPort),
		PublicKey: wireguardInterface.PublicKey,
		Name:      wireguardInterface.Name,
		Enabled:   !wireguardInterface.Disabled,
	}

	return &resolutionData, nil
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

func getInterfaceIpAddress(client RouterOSRawApiClient, name string) (*RouterOSIpAddress, error) {
	reply, err := client.RunArgs("/ip/address/print", fmt.Sprintf("?interface=%s", name))

	if err != nil {
		return nil, err
	}
	if len(reply.Re) != 1 {
		return nil, ErrProviderInterfaceNotFound
	}

	var rosIpAddress RouterOSIpAddress
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosIpAddress); err != nil {
		return nil, err
	}
	return &rosIpAddress, nil
}

func addPeerToInterface(
	client RouterOSRawApiClient,
	interfaceName, pubKey, psk, description string,
	networks []net.IPNet,
	peerAddress net.IP,
) (*WireguardProviderPeer, error) {
	command := []string{
		"/interface/wireguard/peers/add",
	}

	command = append(command,
		buildCreateUpdatePeerCommandArguments(interfaceName, pubKey, psk, description, peerAddress, networks)...,
	)

	logging.Logger.Debugw("ROS add peer to be run",
		"command", utils.SanitizeStringWithValues(strings.Join(command, " "), psk, pubKey),
	)

	reply, err := client.RunArgs(command...)
	if err != nil {
		return nil, err
	}

	retValue, err := routerOSGetReturnValue(reply)
	if err != nil {
		return nil, err
	}

	buildCreateResultNetworks(peerAddress, networks)

	return &WireguardProviderPeer{
		Id:             retValue,
		Rx:             0,
		Tx:             0,
		PublicKey:      pubKey,
		Description:    description,
		Disabled:       false,
		AllowedAddress: buildCreateResultNetworks(peerAddress, networks),
	}, nil

}

func buildCreateResultNetworks(peerAddress net.IP, networks []net.IPNet) []net.IPNet {
	var result []net.IPNet
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/32", peerAddress.String()))
	if err != nil {
		result = append(networks, *network)
	}
	return append(result, networks...)
}

func buildCreateUpdatePeerCommandArguments(interfaceName, pubKey, psk, description string, peerAddress net.IP, networks []net.IPNet) []string {
	command := []string{
		fmt.Sprintf("=interface=%s", interfaceName),
		fmt.Sprintf("=public-key=%s", pubKey),
	}

	if len(psk) != 0 {
		command = append(command, fmt.Sprintf("=preshared-key=%s", psk))
	}

	comment := routerOsCommentPrefix
	if len(description) != 0 {
		comment = comment + ": " + description
	}

	command = append(command, fmt.Sprintf("=comment=%s", comment))

	networksString := fmt.Sprintf("%s/32", peerAddress.String())
	for _, network := range networks {
		networksString = networksString + fmt.Sprintf(",%s", network.String())
	}
	command = append(command, fmt.Sprintf("=allowed-address=%s", strings.Trim(networksString, ",")))
	return command
}

func deletePeersByPublicKeys(client RouterOSRawApiClient, publicKey string, tunnelInfo *models.WireguardTunnelInfo) error {

	peer, err := getPeerByPublicKey(client, publicKey, tunnelInfo)
	if err != nil {
		return err
	}

	commandDelete := []string{
		"/interface/wireguard/peers/remove",
		fmt.Sprintf("=.id=%s", peer.Id),
	}
	logging.Logger.Debugw(
		"ROS delete to be run",
		"command", utils.SanitizeStringWithValues(strings.Join(commandDelete, " "), publicKey),
	)

	_, err = client.RunArgs(commandDelete...)
	return err
}

func getPeerByPublicKey(client RouterOSRawApiClient, publicKey string, tunnelInfo *models.WireguardTunnelInfo) (*WireguardProviderPeer, error) {
	commandQuery := []string{
		"/interface/wireguard/peers/print",
		fmt.Sprintf("?interface=%s", tunnelInfo.Interface.Name),
		fmt.Sprintf("?public-key=%s", publicKey),
	}

	logging.Logger.Debugw(
		"ROS getPeerByPublicKey base query to be run",
		"command", utils.SanitizeStringWithValues(strings.Join(commandQuery, " "), publicKey),
	)

	reply, err := client.RunArgs(commandQuery...)
	if err != nil {
		return nil, err
	}

	if len(reply.Re) != 1 {
		return nil, ErrProviderPeerNotFound
	}

	var peer RouterOSWireguardPeer
	if err := routerOsRawApiDecode(reply.Re[0].Map, &peer); err != nil {
		return nil, err
	}

	return peer.toProviderPeer(), nil
}

func updatePeer(
	client RouterOSRawApiClient,
	id, interfaceName, pubKey, psk, description string,
	networks []net.IPNet,
	peerAddress net.IP,
) (*routeros.Reply, error) {
	updateCommand := []string{
		"/interface/wireguard/peers/set",
		fmt.Sprintf("=.id=%s", id),
	}

	updateCommand = append(updateCommand,
		buildCreateUpdatePeerCommandArguments(interfaceName, pubKey, psk, description, peerAddress, networks)...,
	)
	logging.Logger.Debugw("ROS update peer to be run",
		"command", utils.SanitizeStringWithValues(strings.Join(updateCommand, " "), psk, pubKey),
	)

	return client.RunArgs(updateCommand...)
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
	return strings.Contains(strings.ToLower(errorMsg), routerOsResponseMessageExists)
}

func routerOSResourceNotFoundError(errorMsg string) bool {
	return strings.Contains(strings.ToLower(errorMsg), routerOsResponseMessageNotFound)
}

func routerOSGetReturnValue(reply *routeros.Reply) (string, error) {
	if reply.Done != nil && reply.Done.Word == "!done" {
		if ret, found := reply.Done.Map["ret"]; found {
			return ret, nil
		}
	}
	return "", errors.New("cannot decode routerOS return value from reply")
}
