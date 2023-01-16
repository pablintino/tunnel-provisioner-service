package services

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

const (
	wireguardAsyncRoutineChanSize = 128
	syncPeriod                    = 15 * time.Minute
)

type WireguardPeersService interface {
	BooteableService
	DisposableService
	ListPeers(username string) ([]*models.WireGuardAggregatedPeerModel, error)
	CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireGuardAggregatedPeerModel, error)
	DeletePeer(username, id string) error
	GetPeer(username, id string) (*models.WireGuardAggregatedPeerModel, error)
}

type WireguardPeersServiceImpl struct {
	wireguardPeersRepository repositories.WireguardPeersRepository
	poolService              PoolService
	taskChannel              chan interface{}
	providers                map[string]WireguardTunnelProvider
	tunnelService            WireguardTunnelService
	syncTimer                *time.Ticker
}

type wireguardCreationTask struct {
	Peer              models.WireguardPeerModel
	TunnelInfo        models.WireguardTunnelInfo
	TunnelProfileInfo models.WireguardTunnelProfileInfo
}

type wireguardDeletionTask struct {
	Peer       models.WireguardPeerModel
	TunnelInfo models.WireguardTunnelInfo
}

type wireguardUnprovisionInterfacePeersTask struct {
	TunnelInfo models.WireguardTunnelInfo
}

func NewWireguardPeersService(
	wireguardPeersRepository repositories.WireguardPeersRepository,
	providers map[string]WireguardTunnelProvider,
	poolService PoolService,
	tunnelService WireguardTunnelService,
) *WireguardPeersServiceImpl {

	taskChannel := make(chan interface{}, wireguardAsyncRoutineChanSize)

	wireguardService := &WireguardPeersServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		poolService:              poolService,
		taskChannel:              taskChannel,
		providers:                providers,
		tunnelService:            tunnelService,
	}

	tunnelService.SetTunnelDownCallback(wireguardService.onTunnelDown)
	tunnelService.SetTunnelConfigurationChangeCallback(wireguardService.onTunnelConfigChange)

	return wireguardService
}

func (u *WireguardPeersServiceImpl) OnBoot() error {
	u.handleWireguardSyncTask()
	if u.syncTimer == nil {
		u.syncTimer = time.NewTicker(syncPeriod)
		go u.wireguardAsyncRoutine()
	}
	return nil
}

func (u *WireguardPeersServiceImpl) OnClose() error {
	close(u.taskChannel)
	if u.syncTimer != nil {
		u.syncTimer.Stop()
	}
	return nil
}

func (u *WireguardPeersServiceImpl) ListPeers(username string) ([]*models.WireGuardAggregatedPeerModel, error) {
	peerModels, err := u.wireguardPeersRepository.GetPeersByUsername(username)
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

func (u *WireguardPeersServiceImpl) GetPeer(username, id string) (*models.WireGuardAggregatedPeerModel, error) {
	peer, err := u.wireguardPeersRepository.GetPeerById(username, id)
	if err != nil {
		return nil, err
	} else if peer != nil {
		return u.buildAggregatedPeer(peer)
	} else {
		return nil, nil
	}

}

func (u *WireguardPeersServiceImpl) DeletePeer(username, id string) error {
	peer, err := u.wireguardPeersRepository.GetPeerById(username, id)
	if err != nil {
		return err
	}

	if peer != nil {
		tunnel, err := u.tunnelService.GetTunnelInfo(peer.TunnelId)
		if err != nil && errors.Is(err, ErrServiceNotFoundEntity) {
			return fmt.Errorf("tunnel %s found", peer.TunnelId)
		} else if err != nil {
			return err
		}

		creationTask := wireguardDeletionTask{
			Peer:       *peer, // Pass a mandatory copy (avoid changing the passed reference)
			TunnelInfo: tunnel,
		}
		u.taskChannel <- creationTask
	}
	return nil
}

func (u *WireguardPeersServiceImpl) CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireGuardAggregatedPeerModel, error) {
	tunnel, profile, err := u.tunnelService.GetTunnelConfigById(tunnelId, profileId)
	if err != nil && errors.Is(err, ErrServiceNotFoundEntity) {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", profileId, tunnelId)
	} else if err != nil {
		return nil, err
	}

	// TODO Needs custom error...
	ip, err := u.poolService.GetNextIp(&tunnel)
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

func (u *WireguardPeersServiceImpl) onTunnelDown(tunnelInfo models.WireguardTunnelInfo, _ bool) {
	u.taskChannel <- wireguardUnprovisionInterfacePeersTask{
		TunnelInfo: tunnelInfo,
	}
}
func (u *WireguardPeersServiceImpl) onTunnelConfigChange(tunnelInfo models.WireguardTunnelInfo, keyChanged, endpointChanged bool) {

}

func (u *WireguardPeersServiceImpl) wireguardAsyncRoutine() {
loop:
	for {
		select {
		case p, ok := <-u.taskChannel:
			// Rest/Events side
			if !ok {
				break loop
			}
			switch p := p.(type) {
			case wireguardCreationTask:
				u.handleWireguardCreationTask(p)
			case wireguardDeletionTask:
				u.handleWireguardDeletionTask(p)
			case wireguardUnprovisionInterfacePeersTask:
				u.handleWireguardUnprovisionInterfacePeersTask(p)
			default:
				fmt.Printf("Type of p is %T. Value %v", p, p)
			}
		case _, ok := <-u.syncTimer.C:
			// Sync task side
			if !ok {
				break loop
			}
			u.handleWireguardSyncTask()
		}
	}

	logging.Logger.Debug("Exiting the wireguardAsyncRoutine")
}

func (u *WireguardPeersServiceImpl) handleWireguardSyncTask() {
	// TODO Sync task implementation
}

func (u *WireguardPeersServiceImpl) handleWireguardUnprovisionInterfacePeersTask(task wireguardUnprovisionInterfacePeersTask) {
	provider, ok := u.providers[task.TunnelInfo.Provider]
	if !ok {
		logging.Logger.Errorw(
			"failed to acquire provider",
			"provider", task.TunnelInfo.Provider,
		)
		return
	}

	tunnelPeers, err := u.wireguardPeersRepository.GetPeersByTunnelId(task.TunnelInfo.Id)
	if err != nil {
		logging.Logger.Errorw(
			"task failed to get peers for tunnel",
			"provider", task.TunnelInfo.Provider,
			"interface", task.TunnelInfo.Interface.Name,
			"tunnel", task.TunnelInfo,
			"error", err.Error(),
		)
		return
	}

	toUnprovisionPeers := make(map[string]*models.WireguardPeerModel, 0)
	for _, peer := range tunnelPeers {
		if peer.State == models.ProvisionStateProvisioned {
			peer.State = models.ProvisionStateProvisioning
			if _, err := u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				logging.Logger.Errorw(
					"failed to update peer UNPROVISIONING state for tunnel",
					"provider", task.TunnelInfo.Provider,
					"interface", task.TunnelInfo.Interface.Name,
					"tunnel", task.TunnelInfo,
					"error", err.Error(),
				)
			} else if len(peer.PublicKey) != 0 {
				toUnprovisionPeers[peer.PublicKey] = peer
			}
		}
	}

	var toUnprovisionKeys []string
	for key := range toUnprovisionPeers {
		toUnprovisionKeys = append(toUnprovisionKeys, key)
	}

	if err := u.deletePeersFromProvider(&task.TunnelInfo, provider, toUnprovisionKeys); err != nil {
		// Flag peers as failed to unprovision
		for _, peer := range toUnprovisionPeers {
			peer.ProvisionStatus = err.Error()
			if _, err := u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				logging.Logger.Errorw(
					"failed to update peer UNPROVISIONING status for tunnel",
					"provider", task.TunnelInfo.Provider,
					"interface", task.TunnelInfo.Interface.Name,
					"tunnel", task.TunnelInfo,
					"error", err.Error(),
				)
			}
		}
	} else {
		// Succeed, flag in DB that they are unprovisioned
		for _, peer := range toUnprovisionPeers {
			peer.State = models.ProvisionStateUnprovisioned
			if _, err := u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				logging.Logger.Errorw(
					"failed to update peer to UNPROVISIONED state for tunnel",
					"provider", task.TunnelInfo.Provider,
					"interface", task.TunnelInfo.Interface.Name,
					"tunnel", task.TunnelInfo,
					"error", err.Error(),
				)
			}
		}
	}
}

func (u *WireguardPeersServiceImpl) handleWireguardDeletionTask(task wireguardDeletionTask) {
	provider, ok := u.providers[task.TunnelInfo.Provider]
	if !ok {
		logging.Logger.Errorw(
			"handleWireguardDeletionTask task failed to acquire provider",
			"provider", task.TunnelInfo.Provider,
		)
		return
	}

	task.Peer.State = models.ProvisionStateDeleting
	peer, err := u.wireguardPeersRepository.UpdatePeer(&task.Peer)
	if err != nil {
		logging.Logger.Errorw(
			"failed to set wireguard peer to DELETING state",
			"provider", task.TunnelInfo.Provider,
			"peer", task.Peer,
		)
		return
	}

	u.deletePeerAndIp(&task.TunnelInfo, provider, peer)

}

func (u *WireguardPeersServiceImpl) deletePeerAndIp(
	tunnelInfo *models.WireguardTunnelInfo,
	provider WireguardTunnelProvider,
	peers ...*models.WireguardPeerModel,
) error {
	var publicKeys []string
	for _, peer := range peers {
		if len(peer.PublicKey) != 0 && peer.State != models.ProvisionStateError {
			publicKeys = append(publicKeys, peer.PublicKey)
		}
	}

	err := u.deletePeersFromProvider(tunnelInfo, provider, publicKeys)
	if err != nil {
		logging.Logger.Errorw(
			"deletePeerAndIp failed to delete peers from provider",
			"provider", tunnelInfo.Provider,
			"keys", strings.Join(utils.MasqueradeSensitiveStringSlice(5, publicKeys...), ","),
			"tunnel", tunnelInfo,
		)
	} else {
		for _, peer := range peers {
			err = u.wireguardPeersRepository.DeletePeer(peer)
			if err != nil {
				logging.Logger.Errorw(
					"deletePeerAndIp failed to delete peer from db",
					"provider", tunnelInfo.Provider,
					"peer", peer,
					"tunnel", tunnelInfo,
				)
			}

			if !peer.Ip.IsUnspecified() {
				err = u.poolService.RemoveIp(tunnelInfo, peer.Ip)
				if err != nil {
					logging.Logger.Errorw(
						"deletePeerAndIp failed to delete peer ip from pool",
						"provider", tunnelInfo.Provider,
						"peer", peer,
						"tunnel", tunnelInfo,
						"ip", peer.Ip.String(),
					)
				}
			}
		}
	}
	return err
}

func (u *WireguardPeersServiceImpl) deletePeersFromProvider(tunnelInfo *models.WireguardTunnelInfo, provider WireguardTunnelProvider, publicKeys []string) error {
	if len(publicKeys) == 0 {
		return nil
	}

	// This operation will try to remove all keys if they already exists
	if _, err := provider.TryDeletePeers(tunnelInfo, publicKeys...); err != nil {
		logging.Logger.Errorw(
			"deletePeerAndIp task failed to delete peers",
			"provider", tunnelInfo.Provider,
			"keys", strings.Join(utils.MasqueradeSensitiveStringSlice(5, publicKeys...), ","),
			"tunnel", tunnelInfo,
			"error", err.Error(),
		)
		return err
	}
	return nil
}

func (u *WireguardPeersServiceImpl) handleWireguardCreationTask(task wireguardCreationTask) {
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
		&task.TunnelInfo,
		&task.TunnelProfileInfo,
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

func (u *WireguardPeersServiceImpl) setProvisionError(peer *models.WireguardPeerModel, err error) {
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

func (u *WireguardPeersServiceImpl) buildAggregatedPeer(peer *models.WireguardPeerModel) (*models.WireGuardAggregatedPeerModel, error) {
	tunnel, profile, err := u.tunnelService.GetTunnelConfigById(peer.TunnelId, peer.ProfileId)
	if err != nil && errors.Is(err, ErrServiceNotFoundEntity) {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", peer.ProfileId, peer.TunnelId)
	} else if err != nil {
		return nil, err
	}

	return &models.WireGuardAggregatedPeerModel{
		WireguardPeerModel: *peer,
		Networks:           profile.Ranges,
		Endpoint:           tunnel.Interface.Endpoint,
		RemotePubKey:       tunnel.Interface.PublicKey,
	}, nil
}
