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
	wireguardPeerCreationRetries  = 3
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
	tunnelService            WireguardTunnelService
	usersService             UsersService
	taskChannel              chan interface{}
	providers                map[string]WireguardTunnelProvider
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
	usersService UsersService,
) *WireguardPeersServiceImpl {

	taskChannel := make(chan interface{}, wireguardAsyncRoutineChanSize)

	wireguardService := &WireguardPeersServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		poolService:              poolService,
		taskChannel:              taskChannel,
		providers:                providers,
		tunnelService:            tunnelService,
		usersService:             usersService,
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

	if !checkWireguardPreSharedKeyIsValid(psk) {
		return nil, errors.New("invalid presharedkey")
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

	users, err := u.usersService.GetUserList()
	if err != nil {
		logging.Logger.Errorw(
			"failed to fetch user list in sync task",
			"error", err.Error(),
		)
	}

	var userMap = make(map[string]struct{})
	for _, userName := range users {
		userMap[userName] = struct{}{}
	}

	peers, err := u.wireguardPeersRepository.GetAll()
	if err != nil {
		logging.Logger.Errorw(
			"failed to fetch peers from DB in sync task",
			"error", err.Error(),
		)
	}

	peers = u.syncTaskPeersDelete(userMap, peers)
	u.syncTaskProvision(peers)

}

func (u *WireguardPeersServiceImpl) syncTaskProvision(peers []*models.WireguardPeerModel) {
	// Try re-provision one by one (not already provisioned)
	providerPeersMap, err := u.buildProviderPeersMap()
	if err != nil {
		logging.Logger.Errorw(
			"syncTaskProvision failed to list all peers",
			"error", err.Error(),
		)
		return
	}

	for _, peer := range peers {
		tunnelInfo, profileInfo, err := u.tunnelService.GetTunnelConfigById(peer.TunnelId, peer.ProfileId)
		if err != nil {
			logging.Logger.Errorw(
				"syncTaskProvision failed to get peer tunnel and profile info",
				"peer", peer,
				"error", err.Error(),
			)
			continue
		}

		remotePeer := providerPeersMap[tunnelInfo.Name][peer.PublicKey]

		// Removed by some cause (interface down)
		// Failed ones that need to be retried
		if remotePeer == nil && (peer.State == models.ProvisionStateError || peer.State == models.ProvisionStateUnprovisioned) {
			if err := u.tryProvisionNewPeer(peer, &tunnelInfo, &profileInfo); err != nil {
				logging.Logger.Errorw(
					"syncTaskProvision failed to provision a peer",
					"peer", peer,
					"error", err.Error(),
				)
			}
		} else if peer.State == models.ProvisionStateProvisioned || peer.State == models.ProvisionStateProvisioning ||
			peer.State == models.ProvisionStateUnprovisioned || peer.State == models.ProvisionStateError {
			if err := u.syncTaskTryUpdateProvision(peer, remotePeer, &tunnelInfo, &profileInfo); err != nil {
				logging.Logger.Errorw(
					"syncTaskProvision failed to provision a peer",
					"peer", peer,
					"tunnel", tunnelInfo,
					"profile", profileInfo,
					"error", err.Error(),
				)
			}
		}
	}
}

func (u *WireguardPeersServiceImpl) syncTaskTryUpdateProvision(
	peer *models.WireguardPeerModel,
	remotePeer *WireguardProviderPeer,
	tunnelInfo *models.WireguardTunnelInfo,
	profileInfo *models.WireguardTunnelProfileInfo) error {

	if len(peer.PublicKey) != 0 && remotePeer != nil {
		// Update an existing peer in the provider
		provider, ok := u.providers[tunnelInfo.Provider]
		var err error
		if !ok {
			err = fmt.Errorf("provider %s for tunnel %s found", tunnelInfo.Provider, tunnelInfo.Name)
		} else {

			err = provider.UpdatePeer(
				remotePeer.Id,
				remotePeer.PublicKey,
				peer.Description,
				peer.PreSharedKey,
				tunnelInfo,
				profileInfo,
				peer.Ip,
			)
		}

		if err == nil {
			peer.State = models.ProvisionStateProvisioned
			peer.ProvisionStatus = "" // Reset the provision error status string
			if _, err = u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				u.setProvisionError(peer, err)
			}
		} else {
			u.setProvisionError(peer, err)
		}

		return err
	} else {
		// Provision the hard way (assume new peer in provider)
		return u.tryProvisionNewPeer(peer, tunnelInfo, profileInfo)
	}
}

func (u *WireguardPeersServiceImpl) buildProviderPeersMap() (map[string]map[string]*WireguardProviderPeer, error) {
	tunnelProviders := make(map[string]map[string]*WireguardProviderPeer)
	for _, tunnelInfo := range u.tunnelService.GetTunnels() {
		// Safe to access the providers maps as tunnelInfo comes from config. Always succeed
		peers, err := u.providers[tunnelInfo.Provider].GetPeers(&tunnelInfo)
		if err != nil {
			return nil, err
		}
		for _, peer := range peers {
			tunnelMap, found := tunnelProviders[tunnelInfo.Name]
			if !found {
				tunnelMap = make(map[string]*WireguardProviderPeer)
				tunnelProviders[tunnelInfo.Name] = tunnelMap
			}
			tunnelMap[peer.PublicKey] = peer
		}

	}
	return tunnelProviders, nil
}

func (u *WireguardPeersServiceImpl) syncTaskPeersDelete(userMap map[string]struct{}, peers []*models.WireguardPeerModel) []*models.WireguardPeerModel {
	var toDelete []*models.WireguardPeerModel
	var toUpdate []*models.WireguardPeerModel
	for _, peer := range peers {
		// If user not found or peer is in deleting state just pick up for deletion
		if _, found := userMap[peer.Username]; !found || peer.State == models.ProvisionStateDeleting {
			toDelete = append(toDelete, peer)
		} else {
			toUpdate = append(toUpdate, peer)
		}
	}

	peersByTunnel := make(map[string][]*models.WireguardPeerModel)
	for _, toDeletePeer := range toDelete {
		peersByTunnel[toDeletePeer.TunnelId] = append(peersByTunnel[toDeletePeer.TunnelId], toDeletePeer)
	}

	for tunnelId, tunnelPeers := range peersByTunnel {
		tunnelInfo, err := u.tunnelService.GetTunnelInfo(tunnelId)
		if err != nil {
			// TODO Shouldn't happen as tunnel service will call this service when tunnels change and this service will
			//      maintain the peers collection to have only peers that are associated to a valid tunnel
			// TODO Log
			continue
		}
		if err := u.deletePeerAndIp(&tunnelInfo, u.providers[tunnelInfo.Provider], tunnelPeers...); err != nil {
			// TODO Log
		}
	}
	return toUpdate
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
			peer.State = models.ProvisionStateUnprovisioning
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
	if _, err := provider.TryDeletePeersByPublicKeys(tunnelInfo, publicKeys...); err != nil {
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
	if err := u.tryProvisionNewPeer(&task.Peer, &task.TunnelInfo, &task.TunnelProfileInfo); err != nil {
		logging.Logger.Errorw(
			"handleWireguardCreationTask failed to provision a peer",
			"provider", task.TunnelInfo.Provider,
			"peer", task.Peer,
			"error", err.Error(),
		)
	}
}

func (u *WireguardPeersServiceImpl) tryProvisionNewPeer(
	peer *models.WireguardPeerModel,
	tunnelInfo *models.WireguardTunnelInfo,
	tunnelProfileInfo *models.WireguardTunnelProfileInfo,
) error {

	provider, ok := u.providers[tunnelInfo.Provider]
	if !ok {
		return fmt.Errorf("provider %s for tunnel %s found", tunnelInfo.Provider, tunnelInfo.Name)
	}

	var err error
	if len(peer.PublicKey) == 0 {
		// Create keys and provision
		var keys *WireguardPeerKeyPair
		keys, err = provisionPeerWithoutKey(peer, tunnelInfo, tunnelProfileInfo, provider)
		if err == nil {
			// Store the keys to be saved in DB
			peer.PublicKey = keys.PublicKey
			peer.PrivateKey = keys.PrivateKey
		}

	} else {
		// Just create the peer with the stored keys
		_, err = provider.CreatePeer(
			peer.PublicKey,
			peer.Description,
			peer.PreSharedKey,
			tunnelInfo,
			tunnelProfileInfo,
			peer.Ip,
		)
	}

	if err == nil {
		peer.State = models.ProvisionStateProvisioned
		peer.ProvisionStatus = "" // Reset the provision error status string
		if _, err = u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
			u.setProvisionError(peer, err)
		}
	} else {
		u.setProvisionError(peer, err)
	}
	return err
}

func provisionPeerWithoutKey(peer *models.WireguardPeerModel,
	tunnelInfo *models.WireguardTunnelInfo,
	tunnelProfileInfo *models.WireguardTunnelProfileInfo,
	provider WireguardTunnelProvider) (*WireguardPeerKeyPair, error) {
	for index := 0; index < wireguardPeerCreationRetries; index++ {
		kp, err := buildWireguardApiPair()
		if err != nil {
			return nil, err
		}

		_, err = provider.CreatePeer(kp.PublicKey, peer.Description, peer.PreSharedKey, tunnelInfo, tunnelProfileInfo, peer.Ip)
		if err != nil && routerOSResourceAlreadyExistsError(routerOSRetrieveApiErrorMessage(err)) {
			// Key already exists
			continue
		} else if err != nil {
			return nil, err
		}
		return kp, nil
	}
	return nil, fmt.Errorf("cannot create peer in %d attempts", wireguardPeerCreationRetries)
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
