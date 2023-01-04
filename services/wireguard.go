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
	ListPeers(username string) ([]*models.WireguardPeerModel, error)
	CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireguardPeerModel, error)
	DeletePeer(username, id string) error
	GetPeer(username, id string)  (*models.WireguardPeerModel, error)
	GetTunnels() []*models.WireguardTunnelInfo
	GetTunnelInfo(tunnelId string) *models.WireguardTunnelInfo
	GetProfileInfo(tunnelId, profileId string) *models.WireguardTunnelProfileInfo
	Close()
}

type WireguardServiceImpl struct {
	wireguardPeersRepository repositories.WireguardPeersRepository
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

func NewWireguardService(wireguardPeersRepository repositories.WireguardPeersRepository, config *config.ServiceConfig, providers map[string]WireguardTunnelProvider) (*WireguardServiceImpl, error) {

	taskChannel := make(chan interface{}, wireguardAsyncRoutineChanSize)

	wireguardService := &WireguardServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		taskChannel:              taskChannel,
		tunnels:                  make(map[string]models.WireguardTunnelInfo),
		providers:                providers,
	}
	wireguardService.buildTunnelInfo(config)
	go wireguardService.wireguardAsyncRoutine()

	return wireguardService, nil
}

func (u *WireguardServiceImpl) Close() {
	close(u.taskChannel)
}

func (u *WireguardServiceImpl) ListPeers(username string) ([]*models.WireguardPeerModel, error) {
	return u.wireguardPeersRepository.GetPeers(username)
}

func (u *WireguardServiceImpl) GetPeer(username, id string) (*models.WireguardPeerModel, error) {
	return u.wireguardPeersRepository.GetPeerById(username, id)
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

func (u *WireguardServiceImpl) CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireguardPeerModel, error) {

	profile, profileFound := u.tunnels[tunnelId].Profiles[profileId]
	if !profileFound {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", profileId, tunnelId)
	}
	tunnel := u.tunnels[tunnelId]

	peer := &models.WireguardPeerModel{
		Username:     username,
		Description:  description,
		PreSharedKey: psk,
		State:        models.ProvisionStateProvisioning,
		ProfileId:    profileId,
		TunnelId:     tunnelId,
		CreationTime: time.Now(),
	}

	peer, err := u.wireguardPeersRepository.SavePeer(peer)
	if err != nil {
		logging.Logger.Errorw("Error saving Wireguard Peer", "peer", peer)
		return nil, err
	}

	creationTask := wireguardCreationTask{
		Peer:              *peer, // Pass a mandatory copy (avoid changing the passed reference)
		TunnelProfileInfo: &profile,
		TunnelInfo:        &tunnel,
	}
	u.taskChannel <- creationTask

	return peer, nil
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
			logging.Logger.Errorw("wireguardDeletionTask task failed to acquire provider", "provider", task.TunnelInfo.Provider)
			return
		}

		if err := provider.DeletePeer(task.Peer.PublicKey, task.TunnelInfo); err != nil {
			// TODO This log need String methods properly implemented
			logging.Logger.Errorw("wireguardCreationTask task failed to delete peer", "provider", task.TunnelInfo.Provider, "peer", task.Peer, "tunnel", task.TunnelInfo)
		}
	}
}

func (u *WireguardServiceImpl) handleWireguardCreationTask(task wireguardCreationTask) {
	provider, ok := u.providers[task.TunnelInfo.Provider]
	if !ok {
		logging.Logger.Errorw("wireguardCreationTask task failed to acquire provider", "provider", task.TunnelInfo.Provider)
		return
	}

	keys, err := provider.CreatePeer(task.Peer.Description, task.Peer.PreSharedKey, task.TunnelInfo, task.TunnelProfileInfo)
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
