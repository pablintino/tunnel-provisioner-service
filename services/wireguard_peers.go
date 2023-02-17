package services

import (
	"errors"
	"fmt"
	"net"
	"time"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

const (
	wireguardPeerCreationRetries  = 3
	wireguardAsyncRoutineChanSize = 128

	peerFsmEventProvision   utils.EventType = "Provision"
	peerFsmEventError       utils.EventType = "Error"
	peerFsmEventDelete      utils.EventType = "Delete"
	peerFsmEventForceDelete utils.EventType = "ForceDelete"
	peerFsmEventUnprovision utils.EventType = "Unprovision"
)

type WireguardPeersService interface {
	DisposableService
	GetAggregatedPeersByUsername(username string) ([]*models.WireGuardAggregatedPeerModel, error)
	GetAggregatedPeerByUsernameAndId(username, id string) (*models.WireGuardAggregatedPeerModel, error)
	GetPeers() ([]*models.WireguardPeerModel, error)
	CreatePeer(username, tunnelId, profileId, description, psk string) (*models.WireGuardAggregatedPeerModel, error)
	DeletePeer(username, id string) error
	SyncPeers()
}

type WireguardPeersServiceImpl struct {
	wireguardPeersRepository repositories.WireguardPeersRepository
	poolService              PoolService
	tunnelService            WireguardTunnelService
	usersService             UsersService
	taskChannel              chan interface{}
	providers                map[string]WireguardTunnelProvider
}

type wireguardCreationTask struct {
	Peer models.WireguardPeerModel
}

type wireguardDeletionTask struct {
	Peer       models.WireguardPeerModel
	TunnelInfo models.WireguardTunnelInfo
}

type wireguardSyncTask struct{}

func NewWireguardPeersService(
	wireguardPeersRepository repositories.WireguardPeersRepository,
	providers map[string]WireguardTunnelProvider,
	poolService PoolService,
	tunnelService WireguardTunnelService,
	userService UsersService,
) *WireguardPeersServiceImpl {

	service := &WireguardPeersServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		poolService:              poolService,
		taskChannel:              make(chan interface{}, wireguardAsyncRoutineChanSize),
		providers:                providers,
		tunnelService:            tunnelService,
		usersService:             userService,
	}
	go service.wireguardAsyncRoutine()

	return service
}

func (u *WireguardPeersServiceImpl) OnClose() {
	close(u.taskChannel)
}

func (u *WireguardPeersServiceImpl) GetAggregatedPeersByUsername(username string) ([]*models.WireGuardAggregatedPeerModel, error) {
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

func (u *WireguardPeersServiceImpl) GetPeers() ([]*models.WireguardPeerModel, error) {
	return u.wireguardPeersRepository.GetAll()
}

func (u *WireguardPeersServiceImpl) SyncPeers() {
	u.taskChannel <- wireguardSyncTask{}
}

func (u *WireguardPeersServiceImpl) GetAggregatedPeerByUsernameAndId(username, id string) (*models.WireGuardAggregatedPeerModel, error) {
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
	_, profile, err := u.tunnelService.GetTunnelConfigById(tunnelId, profileId)
	if err != nil && errors.Is(err, ErrServiceNotFoundEntity) {
		return nil, fmt.Errorf("profile %s not for tunnel %s found", profileId, tunnelId)
	} else if err != nil {
		return nil, err
	}

	if !checkWireguardPreSharedKeyIsValid(psk) {
		return nil, errors.New("invalid presharedkey")
	}

	peer := &models.WireguardPeerModel{
		Username:     username,
		Description:  description,
		PreSharedKey: psk,
		State:        models.ProvisionStateCreated,
		ProfileId:    profileId,
		TunnelId:     tunnelId,
		Ip:           net.IPv4zero,
		CreationTime: time.Now(),
	}

	peer, err = u.wireguardPeersRepository.SavePeer(peer)
	if err != nil {
		logging.Logger.Errorw("Error saving Wireguard Peer", "peer", peer)
		return nil, err
	}

	creationTask := wireguardCreationTask{
		Peer: *peer, // Pass a mandatory copy (avoid changing the passed reference)
	}
	u.taskChannel <- creationTask

	return &models.WireGuardAggregatedPeerModel{WireguardPeerModel: *peer, Networks: profile.Ranges}, nil
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
			case wireguardSyncTask:
				u.handleWireguardSyncTask()
			default:
				fmt.Printf("Type of p is %T. Value %v", p, p)
			}
		}
	}

	logging.Logger.Debug("Exiting the wireguardAsyncRoutine")
}

func (u *WireguardPeersServiceImpl) handleWireguardSyncTask() {

	users, err := u.usersService.GetUsers()
	if err != nil {
		logging.Logger.Errorw(
			"sync failed to get users",
			"error", err.Error(),
		)
		return
	}

	peers, err := u.wireguardPeersRepository.GetAll()
	if err != nil {
		logging.Logger.Errorw(
			"sync failed to get peers",
			"error", err.Error(),
		)
		return
	}

	tunnels := u.tunnelService.GetTunnels()

	for _, peer := range peers {
		tunnel, tunnelFound := tunnels[peer.TunnelId]
		if !tunnelFound {
			u.sendEventToPeerFsm(peerFsmEventForceDelete, peer)
		} else if _, userFound := users[peer.Username]; !userFound {
			u.sendEventToPeerFsm(peerFsmEventDelete, peer)
		} else if !tunnel.Interface.Present {
			u.sendEventToPeerFsm(peerFsmEventUnprovision, peer)
		} else {
			u.sendEventToPeerFsm(peerFsmEventProvision, peer)
		}
	}
}

func (u *WireguardPeersServiceImpl) handleWireguardCreationTask(task wireguardCreationTask) {
	u.sendEventToPeerFsm(peerFsmEventProvision, &task.Peer)
}

func (u *WireguardPeersServiceImpl) handleWireguardDeletionTask(task wireguardDeletionTask) {
	u.sendEventToPeerFsm(peerFsmEventDelete, &task.Peer)
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
