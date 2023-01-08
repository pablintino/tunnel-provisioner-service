package services

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

type PoolService interface {
	GetNextIp(tunnel *models.WireguardTunnelInfo) (net.IP, error)
	RemoveIp(tunnel *models.WireguardTunnelInfo, ip net.IP) error
}

type PoolServiceImpl struct {
	ipPoolRepository repositories.IpPoolRepository
	providers        map[string]WireguardTunnelProvider
	ipMutex          sync.Mutex
}

func NewPoolService(ipPoolRepository repositories.IpPoolRepository, providers map[string]WireguardTunnelProvider) *PoolServiceImpl {
	return &PoolServiceImpl{ipPoolRepository: ipPoolRepository, providers: providers}
}

func (p *PoolServiceImpl) RemoveIp(tunnel *models.WireguardTunnelInfo, ip net.IP) error {
	// Can only be accessed by one goroutine
	p.ipMutex.Lock()
	defer p.ipMutex.Unlock()

	pool, err := p.ipPoolRepository.GetPool(tunnel.Provider, tunnel.Name)
	if err != nil {
		return err
	}

	if pool == nil {
		return fmt.Errorf("cannot find IP Pool for %s provider and %s tunnel", tunnel.Provider, tunnel.Name)
	}

	inUse, err := removeIpFromUsedSlice(ip, pool.InUse)
	if err != nil {
		return err
	}

	pool.InUse = inUse
	_, err = p.ipPoolRepository.UpdatePool(pool)
	if err != nil {
		return err
	}

	return nil
}

func (p *PoolServiceImpl) GetNextIp(tunnel *models.WireguardTunnelInfo) (net.IP, error) {
	// Can only be accessed by one goroutine
	p.ipMutex.Lock()
	defer p.ipMutex.Unlock()

	pool, err := p.ipPoolRepository.GetPool(tunnel.Provider, tunnel.Name)
	if err != nil {
		return nil, err
	}

	if pool == nil {
		pool, err = p.createIpPool(tunnel)
		if err != nil {
			return nil, err
		}
	}

	next, err := getNextIp(pool.Network, append(pool.InUse, pool.Reserved...)...)
	if err != nil {
		return nil, err
	}

	pool.InUse = append(pool.InUse, next)
	_, err = p.ipPoolRepository.UpdatePool(pool)
	if err != nil {
		return nil, err
	}

	return next, nil
}

func (p *PoolServiceImpl) createIpPool(tunnel *models.WireguardTunnelInfo) (*models.IpPoolModel, error) {
	provider, found := p.providers[tunnel.Provider]
	if !found {
		return nil, errors.New(fmt.Sprintf("cannot get pool ip cause cannot find %s provider", tunnel.Provider))
	}

	ip, network, err := provider.GetInterfaceIp(tunnel.Interface)
	if err != nil {
		return nil, err
	}

	pool := &models.IpPoolModel{
		Provider: tunnel.Provider,
		Tunnel:   tunnel.Name,
		Network:  *network,
		Reserved: []net.IP{ip}, // Interface address is reserved by default
		InUse:    []net.IP{},
	}

	pool, err = p.ipPoolRepository.SavePool(pool)
	if err != nil {
		return nil, err
	}
	return pool, nil
}

func getNextIp(network net.IPNet, used ...net.IP) (net.IP, error) {
	mb := make(map[string]struct{}, len(used))
	for _, x := range used {
		mb[x.String()] = struct{}{}
	}

	isIpv4 := len(network.IP.To4()) == net.IPv4len

	var broadcastAddress, networkAddress net.IP
	if isIpv4 {
		broadcastAddress = utils.BroadcastIpv4Addr(network)
		networkAddress = utils.NetworkIpv4Addr(network)
	} else {
		networkAddress = net.IPv6unspecified
		broadcastAddress = net.IPv6unspecified
	}

	for ip := network.IP.To16(); network.Contains(ip); ip = utils.IncrementIP(ip) {
		_, found := mb[ip.String()]
		if (!isIpv4 || !ip.Equal(broadcastAddress) && !ip.Equal(networkAddress)) && !found {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("cannot found empty IP for network %s", network.String())
}

func removeIpFromUsedSlice(ip net.IP, inUse []net.IP) ([]net.IP, error) {
	removeIdx := -1
	for i, elem := range inUse {
		if elem.Equal(ip) {
			removeIdx = i
			break
		}
	}

	if removeIdx == -1 {
		return nil, fmt.Errorf("cannot remove ip from in use list cause not found %s", ip.String())
	}

	return append(inUse[:removeIdx], inUse[removeIdx+1:]...), nil
}
