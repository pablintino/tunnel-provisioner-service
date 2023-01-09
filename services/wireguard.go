package services

import (
	"bytes"
	"fmt"
	"net"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

const (
	wireguardAsyncRoutineChanSize = 128
)

type WireguardService interface {
	ListPeers(username string) ([]*models.WireGuardAggregatedPeerModel, error)
	CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireGuardAggregatedPeerModel, error)
	DeletePeer(username, id string) error
	GetPeer(username, id string) (*models.WireGuardAggregatedPeerModel, error)
	GetTunnels() []*models.WireguardTunnelInfo
	GetTunnelInfo(tunnelId string) *models.WireguardTunnelInfo
	GetProfileInfo(tunnelId, profileId string) *models.WireguardTunnelProfileInfo
	Close()
}

type WireguardServiceImpl struct {
	wireguardPeersRepository repositories.WireguardPeersRepository
	poolService              PoolService
	taskChannel              chan interface{}
	tunnels                  map[string]models.WireguardTunnelInfo
	providers                map[string]WireguardTunnelProvider
}

type wireguardCreationTask struct {
	Peer              models.WireguardPeerModel
	TunnelInfo        *models.WireguardTunnelInfo
	TunnelProfileInfo *models.WireguardTunnelProfileInfo
}

type wireguardDeletionTask struct {
	Peer       models.WireguardPeerModel
	TunnelInfo *models.WireguardTunnelInfo
}

func NewWireguardService(
	wireguardPeersRepository repositories.WireguardPeersRepository,
	config *config.ServiceConfig,
	providers map[string]WireguardTunnelProvider,
	poolService PoolService,
) (*WireguardServiceImpl, error) {

	taskChannel := make(chan interface{}, wireguardAsyncRoutineChanSize)

	wireguardService := &WireguardServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		poolService:              poolService,
		taskChannel:              taskChannel,
		tunnels:                  make(map[string]models.WireguardTunnelInfo),
		providers:                providers,
	}
	wireguardService.buildTunnelInfo(config)
	go wireguardService.wireguardAsyncRoutine()

	for _, prov := range providers {
		prov.SubscribePublicDNSResolution(wireguardService.onDdnsResolution)
	}

	return wireguardService, nil
}

func (u *WireguardServiceImpl) Close() {
	close(u.taskChannel)
}

func (u *WireguardServiceImpl) ListPeers(username string) ([]*models.WireGuardAggregatedPeerModel, error) {
	peerModels, err := u.wireguardPeersRepository.GetPeers(username)
	if err != nil {
		return nil, err
	}
	peers := make([]*models.WireGuardAggregatedPeerModel, 0)
	for _, peerModel := range peerModels {
		aggPeer, err := u.buildAggregatedPeer(peerModel)
		if err != nil {
			return nil, err
		}

		peers = append(peers, aggPeer)
	}

	return peers, nil
}

func (u *WireguardServiceImpl) GetPeer(username, id string) (*models.WireGuardAggregatedPeerModel, error) {
	peer, err := u.wireguardPeersRepository.GetPeerById(username, id)
	if err != nil {
		return nil, err
	} else if peer != nil {
		return u.buildAggregatedPeer(peer)
	} else {
		return nil, nil
	}

}

func (u *WireguardServiceImpl) DeletePeer(username, id string) error {
	peer, err := u.wireguardPeersRepository.DeletePeer(username, id)
	if err != nil {
		return err
	}

	if peer != nil {
		tunnel, tunnelFound := u.tunnels[peer.TunnelId]
		if !tunnelFound {
			return fmt.Errorf("tunnel %s not for %s peer", peer.TunnelId, id)
		}

		creationTask := wireguardDeletionTask{
			Peer:       *peer, // Pass a mandatory copy (avoid changing the passed reference)
			TunnelInfo: &tunnel,
		}
		u.taskChannel <- creationTask
	}
	return nil
}

func (u *WireguardServiceImpl) CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireGuardAggregatedPeerModel, error) {
	tunnel, profile := u.getTunnelConfigById(tunnelId, profileId)
	if tunnel == nil || profile == nil {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", profileId, tunnelId)
	}

	// TODO Needs custom error...
	ip, err := u.poolService.GetNextIp(tunnel)
	if err != nil {
		return nil, err
	}

	peer := &models.WireguardPeerModel{
		Username:     username,
		Description:  description,
		PreSharedKey: psk,
		State:        models.ProvisionStateProvisioning,
		ProfileId:    profileId,
		TunnelId:     tunnelId,
		Ip:           ip,
		CreationTime: time.Now(),
	}

	peer, err = u.wireguardPeersRepository.SavePeer(peer)
	if err != nil {
		logging.Logger.Errorw("Error saving Wireguard Peer", "peer", peer)
		return nil, err
	}

	creationTask := wireguardCreationTask{
		Peer:              *peer, // Pass a mandatory copy (avoid changing the passed reference)
		TunnelProfileInfo: profile,
		TunnelInfo:        tunnel,
	}
	u.taskChannel <- creationTask

	return &models.WireGuardAggregatedPeerModel{WireguardPeerModel: *peer, Networks: profile.Ranges}, nil
}

func (u *WireguardServiceImpl) GetTunnels() []*models.WireguardTunnelInfo {
	tunnels := make([]*models.WireguardTunnelInfo, 0)
	for _, v := range u.tunnels {
		tunnels = append(tunnels, &v)
	}
	return tunnels
}

func (u *WireguardServiceImpl) GetTunnelInfo(tunnelId string) *models.WireguardTunnelInfo {
	if tunnel, ok := u.tunnels[tunnelId]; ok {
		return &tunnel
	}
	return nil
}

func (u *WireguardServiceImpl) GetProfileInfo(tunnelId, profileId string) *models.WireguardTunnelProfileInfo {
	if profile, ok := u.tunnels[tunnelId].Profiles[profileId]; ok {
		return &profile
	}
	return nil
}

func (u *WireguardServiceImpl) onDdnsResolution(provider string, iface WireguardInterface) {
	logging.Logger.Infow("onDdnsResolution", "iface", iface)
}

func (u *WireguardServiceImpl) wireguardAsyncRoutine() {
	for {
		p, ok := <-u.taskChannel
		if !ok {
			logging.Logger.Debug("Exiting the wireguardAsyncRoutine")
			return
		}
		switch p := p.(type) {
		case wireguardCreationTask:
			u.handleWireguardCreationTask(p)
		case wireguardDeletionTask:
			u.handleWireguardDeletionTask(p)
		default:
			fmt.Printf("Type of p is %T. Value %v", p, p)
		}

	}
}

func (u *WireguardServiceImpl) handleWireguardDeletionTask(task wireguardDeletionTask) {
	if task.Peer.State == models.ProvisionStateProvisioned && len(task.Peer.PublicKey) != 0 {
		provider, ok := u.providers[task.TunnelInfo.Provider]
		if !ok {
			logging.Logger.Errorw(
				"handleWireguardDeletionTask task failed to acquire provider",
				"provider", task.TunnelInfo.Provider,
			)
			return
		}

		if !task.Peer.Ip.IsUnspecified() {
			err := u.poolService.RemoveIp(task.TunnelInfo, task.Peer.Ip)
			if err != nil {
				// TODO This log need String methods properly implemented
				logging.Logger.Errorw(
					"handleWireguardDeletionTask task failed to delete peer ip from pool",
					"provider", task.TunnelInfo.Provider,
					"peer", task.Peer,
					"tunnel", task.TunnelInfo,
					"ip", task.Peer.Ip.String(),
				)
			}
		}

		if err := provider.DeletePeer(task.Peer.PublicKey, task.TunnelInfo); err != nil {
			// TODO This log need String methods properly implemented
			logging.Logger.Errorw(
				"wireguardCreationTask task failed to delete peer",
				"provider", task.TunnelInfo.Provider,
				"peer", task.Peer,
				"tunnel", task.TunnelInfo,
			)
		}
	}
}

func (u *WireguardServiceImpl) handleWireguardCreationTask(task wireguardCreationTask) {
	provider, ok := u.providers[task.TunnelInfo.Provider]
	if !ok {
		logging.Logger.Errorw(
			"handleWireguardCreationTask failed to acquire provider",
			"provider", task.TunnelInfo.Provider,
		)
		return
	}

	keys, err := provider.CreatePeer(
		task.Peer.Description,
		task.Peer.PreSharedKey,
		task.TunnelInfo,
		task.TunnelProfileInfo,
		task.Peer.Ip,
	)

	if err == nil {
		task.Peer.PublicKey = keys.PublicKey
		task.Peer.PrivateKey = keys.PrivateKey
		task.Peer.State = models.ProvisionStateProvisioned

		if _, err := u.wireguardPeersRepository.UpdatePeer(&task.Peer); err != nil {
			u.setProvisionError(&task.Peer, err)
		}
	} else {
		u.setProvisionError(&task.Peer, err)
	}
}

func (u *WireguardServiceImpl) setProvisionError(peer *models.WireguardPeerModel, err error) {
	peer.ProvisionStatus = err.Error()
	peer.State = models.ProvisionStateError
	if _, updateErr := u.wireguardPeersRepository.UpdatePeer(peer); updateErr != nil {
		logging.Logger.Errorw(
			"error updating peer provision state to error",
			"original-error", err.Error(),
			"update-error", err,
			"peer", peer.Id.Hex(),
		)
	}
}

func (u *WireguardServiceImpl) buildTunnelInfo(config *config.ServiceConfig) {
	for providerName, provider := range config.Providers.RouterOS {
		for tunnelName, tunnelConfig := range provider.WireguardTunnels {
			profiles := make(map[string]models.WireguardTunnelProfileInfo, 0)
			for profName, profile := range tunnelConfig.Profiles {
				ranges := make([]net.IPNet, 0)
				for _, ipRange := range profile.Ranges {
					ranges = appendProfileRange(ipRange, ranges)
				}
				profileId := utils.GenerateInternalIdFromString(profName)
				profiles[profileId] = models.WireguardTunnelProfileInfo{
					Name:   profName,
					Ranges: ranges,
					Id:     profileId,
				}
			}

			tunnelId := utils.GenerateInternalIdFromString(tunnelName)
			u.tunnels[tunnelId] = models.WireguardTunnelInfo{
				Id:        tunnelId,
				Name:      tunnelName,
				Provider:  providerName,
				Interface: tunnelConfig.Interface,
				Profiles:  profiles,
			}

		}
	}
}

func (u *WireguardServiceImpl) buildAggregatedPeer(peer *models.WireguardPeerModel) (*models.WireGuardAggregatedPeerModel, error) {
	tunnel, profile := u.getTunnelConfigById(peer.TunnelId, peer.ProfileId)
	if tunnel == nil || profile == nil {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", peer.TunnelId, peer.ProfileId)
	}

	return &models.WireGuardAggregatedPeerModel{WireguardPeerModel: *peer, Networks: profile.Ranges}, nil
}

func appendProfileRange(networkRange string, ranges []net.IPNet) []net.IPNet {
	// Ignore error as config was validated before and ranges are parseable at this point
	_, netRange, _ := net.ParseCIDR(networkRange)

	for _, rangeAt := range ranges {
		if netRange.IP.Equal(rangeAt.IP) && bytes.Equal((*netRange).Mask, rangeAt.Mask) {
			return ranges
		}
	}

	return append(ranges, *netRange)
}

func (u *WireguardServiceImpl) getTunnelConfigById(tunnelId, profileId string) (*models.WireguardTunnelInfo, *models.WireguardTunnelProfileInfo) {
	if profile, ok := u.tunnels[tunnelId].Profiles[profileId]; !ok {
		return nil, nil
	} else {
		tunnel := u.tunnels[tunnelId]
		return &tunnel, &profile
	}
}
