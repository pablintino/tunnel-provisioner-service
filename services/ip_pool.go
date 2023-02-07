package services

import (
	"fmt"
	"net"
	"sync"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

type PoolService interface {
	GetNextIp(tunnelInfo *models.WireguardTunnelInfo) (net.IP, error)
	RemoveIp(tunnelInfo *models.WireguardTunnelInfo, ip net.IP) error
	DeletePool(tunnelInfo *models.WireguardTunnelInfo) error
}

type PoolServiceImpl struct {
	ipPoolRepository repositories.IpPoolRepository
	providers        map[string]WireguardTunnelProvider
	ipMutex          sync.Mutex
}

func NewPoolService(ipPoolRepository repositories.IpPoolRepository, providers map[string]WireguardTunnelProvider) *PoolServiceImpl {
	return &PoolServiceImpl{ipPoolRepository: ipPoolRepository, providers: providers}
}

func (p *PoolServiceImpl) DeletePool(tunnelInfo *models.WireguardTunnelInfo) error {
	// Can only be accessed by one goroutine
	p.ipMutex.Lock()
	defer p.ipMutex.Unlock()
	return p.ipPoolRepository.DeleteTunnelPool(tunnelInfo.Provider, tunnelInfo.Name)

}

func (p *PoolServiceImpl) RemoveIp(tunnelInfo *models.WireguardTunnelInfo, ip net.IP) error {
	// Can only be accessed by one goroutine
	p.ipMutex.Lock()
	defer p.ipMutex.Unlock()

	pool, err := p.ipPoolRepository.GetPool(tunnelInfo.Provider, tunnelInfo.Name)
	if err != nil {
		return err
	}

	if pool == nil {
		return fmt.Errorf("cannot find IP Pool for %s provider and %s tunnel", tunnelInfo.Provider, tunnelInfo.Name)
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

func (p *PoolServiceImpl) GetNextIp(tunnelInfo *models.WireguardTunnelInfo) (net.IP, error) {
	// Can only be accessed by one goroutine
	p.ipMutex.Lock()
	defer p.ipMutex.Unlock()

	pool, err := p.ipPoolRepository.GetPool(tunnelInfo.Provider, tunnelInfo.Name)
	if err != nil {
		return nil, err
	}

	if pool == nil {
		pool, err = p.createIpPool(tunnelInfo)
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

func (p *PoolServiceImpl) createIpPool(tunnelInfo *models.WireguardTunnelInfo) (*models.IpPoolModel, error) {
	provider, found := p.providers[tunnelInfo.Provider]
	if !found {
		return nil, fmt.Errorf("cannot get pool ip cause cannot find %s provider", tunnelInfo.Provider)
	}

	ip, network, err := provider.GetInterfaceIp(tunnelInfo.Interface.Name)
	if err != nil {
		return nil, err
	}

	pool := &models.IpPoolModel{
		Provider: tunnelInfo.Provider,
		Tunnel:   tunnelInfo.Name,
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
