package services

import (
	"errors"
	"fmt"
	"github.com/mitchellh/mapstructure"
	"gopkg.in/routeros.v2"
	"net"
	"strings"
	"sync"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"
)

const (
	routerOsKeyCreationRetries = 3
	routerOsPoolSize           = 5
	clientLifeTime             = 1 * time.Minute
	routerOsApiDialTimeout     = 20 * time.Second
)

type RouterOSWireguardPeer struct {
	PublicKey              string      `mapstructure:"public-key""`
	EndpointPort           int         `mapstructure:"endpoint-port"`
	CurrentEndpointAddress string      `mapstructure:"current-endpoint-address"`
	AllowedAddress         []net.IPNet `mapstructure:"allowed-address"`
	Tx                     int         `mapstructure:"tx""`
	Comment                string      `mapstructure:"comment"`
	Id                     string      `mapstructure:".id"`
	Interface              string      `mapstructure:"interface"`
	EndpointAddress        string      `mapstructure:"endpoint-address"`
	CurrentEndpointPort    int         `mapstructure:"current-endpoint-port"`
	Rx                     int         `mapstructure:"rx"`
	Disabled               bool        `mapstructure:"disabled"`
}

type RouterOSIpAddress struct {
	Id              string        `mapstructure:".id"`
	Address         utils.IPSlash `mapstructure:"address"`
	Network         net.IP        `mapstructure:"network"` // Network base address, not an IP+Netmask
	Interface       string        `mapstructure:"interface"`
	ActualInterface string        `mapstructure:"actual-interface"`
	Disabled        bool          `mapstructure:"disabled"`
	Dynamic         bool          `mapstructure:"dynamic"`
	Invalid         bool          `mapstructure:"invalid"`
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
	config := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToIPHookFunc(),
			mapstructure.StringToIPNetHookFunc(),
			utils.StringToIPSlashHookFunc(),
			mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToSliceHookFunc(","),
				utils.StringToIPSlashHookFunc(),
				mapstructure.StringToIPNetHookFunc(),
				mapstructure.StringToIPHookFunc(),
			),
		),
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return err
	}

	return decoder.Decode(input)
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

func (p *ROSClientPool) releaseClient(client RouterOSRawApiClient) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, entry := range p.clients {
		if entry.client == client {
			entry.inUse = false
		}
	}
	return errors.New("client to be released not found")
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

type ROSWireguardRouterProvider struct {
	config     *config.RouterOSProviderConfig
	clientPool *ROSClientPool
}

func NewROSWireguardRouterProvider(
	config *config.RouterOSProviderConfig,
	clientFactory func(config *config.RouterOSProviderConfig) (RouterOSRawApiClient, error),
) *ROSWireguardRouterProvider {
	return &ROSWireguardRouterProvider{config: config, clientPool: NewROSClientPool(config, clientFactory)}
}

func (p *ROSWireguardRouterProvider) DeletePeer(publicKey string, _ *models.WireguardTunnelInfo) error {
	_, err := p.clientPool.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
		return deletePeer(rawClient, publicKey)
	})
	return err
}

func (p *ROSWireguardRouterProvider) GetInterfaceIp(name string) (net.IP, *net.IPNet, error) {
	reply, err := p.clientPool.RunOnPool(func(rawClient RouterOSRawApiClient) (*routeros.Reply, error) {
		return rawClient.RunArgs("/ip/address/print", fmt.Sprintf("?interface=%s", name))
	})

	if err != nil {
		return nil, nil, err
	}
	if len(reply.Re) != 1 {
		return nil, nil, errors.New(fmt.Sprintf("cannot find interface %s", name))
	}

	var rosIpAddress RouterOSIpAddress
	if err := routerOsRawApiDecode(reply.Re[0].Map, &rosIpAddress); err != nil {
		return nil, nil, err
	}

	netIp, netMask := utils.AlignNetMask(rosIpAddress.Network, rosIpAddress.Address.Mask)
	return rosIpAddress.Address.IP, &net.IPNet{IP: netIp, Mask: netMask}, nil
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

	logging.Logger.Debugw("ROS add peer to be run", "command", sanitizePskPubKeyCommand(strings.Join(command, " "), psk, pubKey))

	return client.RunArgs(command...)
}

func deletePeer(client RouterOSRawApiClient, pubKey string) (*routeros.Reply, error) {
	commandQuery := []string{
		"/interface/wireguard/peers/print",
		fmt.Sprintf("?public-key=%s", pubKey),
	}

	logging.Logger.Debugw(
		"ROS find by pubkey query to be run",
		"command", sanitizePskPubKeyCommand(strings.Join(commandQuery, " "), pubKey),
	)

	reply, err := client.RunArgs(commandQuery...)
	if err != nil {
		return nil, err
	}
	if len(reply.Re) != 1 {
		return nil, errors.New("cannot find peer to be deleted")
	}

	var peer RouterOSWireguardPeer
	if err := routerOsRawApiDecode(reply.Re[0].Map, &peer); err != nil {
		return nil, err
	}

	if peer.Id == "" {
		return nil, errors.New("cannot determine peer Id to be deleted")
	}

	commandDelete := []string{
		"/interface/wireguard/peers/remove",
		fmt.Sprintf("=.id=%s", peer.Id),
	}
	logging.Logger.Debugw(
		"ROS delete to be run",
		"command", strings.Join(commandDelete, " "),
	)

	replyDelete, err := client.RunArgs(commandDelete...)
	if err != nil {
		return nil, err
	}
	return replyDelete, err
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
