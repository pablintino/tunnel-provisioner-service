package services

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

const (
	wireguardAsyncRoutineChanSize = 128
	syncPeriod                    = 15 * time.Minute
)

type WireguardService interface {
	BooteableService
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
	wireguardPeersRepository      repositories.WireguardPeersRepository
	wireguardInterfacesRepository repositories.WireguardInterfacesRepository
	poolService                   PoolService
	taskChannel                   chan interface{}
	tunnels                       map[string]models.WireguardTunnelInfo
	providers                     map[string]WireguardTunnelProvider
	interfaces                    map[string]map[string]models.WireguardInterfaceModel
	syncTimer                     *time.Ticker
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

type wireguardUnprovisionInterfacePeersTask struct {
	Provider  string
	Interface string
}

func NewWireguardService(
	wireguardPeersRepository repositories.WireguardPeersRepository,
	wireguardInterfacesRepository repositories.WireguardInterfacesRepository,
	config *config.ServiceConfig,
	providers map[string]WireguardTunnelProvider,
	poolService PoolService,
) *WireguardServiceImpl {

	taskChannel := make(chan interface{}, wireguardAsyncRoutineChanSize)

	wireguardService := &WireguardServiceImpl{
		wireguardPeersRepository:      wireguardPeersRepository,
		wireguardInterfacesRepository: wireguardInterfacesRepository,
		poolService:                   poolService,
		taskChannel:                   taskChannel,
		tunnels:                       make(map[string]models.WireguardTunnelInfo),
		providers:                     providers,
		interfaces:                    make(map[string]map[string]models.WireguardInterfaceModel),
	}
	wireguardService.buildTunnelInfo(config)

	for _, prov := range providers {
		prov.SubscribeTunnelInterfaceResolution(wireguardService.onTunnelInterfaceResolution)
	}

	return wireguardService
}

func (u *WireguardServiceImpl) OnBoot() error {
	u.handleWireguardSyncTask()
	if u.syncTimer == nil {
		u.syncTimer = time.NewTicker(syncPeriod)
		go u.wireguardAsyncRoutine()
	}
	return nil
}

func (u *WireguardServiceImpl) Close() {
	close(u.taskChannel)
	if u.syncTimer != nil {
		u.syncTimer.Stop()
	}
}

func (u *WireguardServiceImpl) ListPeers(username string) ([]*models.WireGuardAggregatedPeerModel, error) {
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
	peer, err := u.wireguardPeersRepository.GetPeerById(username, id)
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
		Username:      username,
		Description:   description,
		PreSharedKey:  psk,
		State:         models.ProvisionStateProvisioning,
		ProfileId:     profileId,
		TunnelId:      tunnelId,
		Ip:            ip,
		InterfaceName: tunnel.Interface,
		CreationTime:  time.Now(),
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

func (u *WireguardServiceImpl) onTunnelInterfaceResolution(provider string, resolutionData []WireguardInterfaceResolutionData) {

	// Replace or create the interfaces map of the provider
	interfacesMap := make(map[string]models.WireguardInterfaceModel)
	u.interfaces[provider] = interfacesMap

	for _, ifaceResolutionData := range resolutionData {
		newIface := models.WireguardInterfaceModel{
			Name:      ifaceResolutionData.Name,
			PublicKey: ifaceResolutionData.PublicKey,
			Endpoint:  ifaceResolutionData.Endpoint,
			Provider:  provider,
		}
		interfacesMap[ifaceResolutionData.Name] = newIface
	}

	u.processInterfaceChanges(provider, interfacesMap)
}

func (u *WireguardServiceImpl) processInterfaceChanges(provider string, updatedInterfaces map[string]models.WireguardInterfaceModel) {
	providerInterfaces, err := u.wireguardInterfacesRepository.GetProviderInterfaces(provider)
	if err != nil {
		logging.Logger.Errorw(
			"processInterfaceChanges failed to query db to retrieve wireguard interfaces",
			"provider", provider,
			"error", err.Error(),
		)
		return
	}

	for _, providerInterface := range providerInterfaces {
		newIface, found := updatedInterfaces[providerInterface.Name]
		if !found {
			// Interface removed. Notify and unprovision its peers
			// TODO
			unprovisionTask := wireguardUnprovisionInterfacePeersTask{
				Interface: providerInterface.Name,
				Provider:  provider,
			}
			u.taskChannel <- unprovisionTask
		} else if !reflect.DeepEqual(newIface, providerInterface) {
			// Interface changed. Notify
			// TODO
		}
	}

	if len(providerInterfaces) != 0 {
		if err := u.wireguardInterfacesRepository.RemoveAll(provider); err != nil {
			logging.Logger.Errorw(
				"processInterfaceChanges failed to drop interfaces of the given provider from database",
				"provider", provider,
				"error", err.Error(),
			)
		}
	}

	for _, iface := range updatedInterfaces {
		if _, err := u.wireguardInterfacesRepository.Save(&iface); err != nil {
			logging.Logger.Errorw(
				"processInterfaceChanges failed to save interface info",
				"provider", provider,
				"error", err.Error(),
				"iface", iface,
			)
		}
	}
}

func (u *WireguardServiceImpl) wireguardAsyncRoutine() {
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

func (u *WireguardServiceImpl) handleWireguardSyncTask() {
	// TODO Sync task implementation
}

func (u *WireguardServiceImpl) handleWireguardUnprovisionInterfacePeersTask(task wireguardUnprovisionInterfacePeersTask) {
	tunnelInfo := u.getTunnelInfoByInterfaceAndProvider(task.Interface, task.Provider)
	if tunnelInfo == nil {
		logging.Logger.Errorw(
			"failed to acquire tunnel info",
			"provider", task.Provider,
			"interface", task.Interface,
		)
		return
	}

	provider, ok := u.providers[tunnelInfo.Provider]
	if !ok {
		logging.Logger.Errorw(
			"failed to acquire provider",
			"provider", tunnelInfo.Provider,
		)
		return
	}

	tunnelPeers, err := u.wireguardPeersRepository.GetPeersByTunnelId(tunnelInfo.Id)
	if err != nil {
		logging.Logger.Errorw(
			"task failed to get peers for tunnel",
			"provider", task.Provider,
			"interface", task.Interface,
			"tunnel", tunnelInfo,
		)
	}

	toUnprovisionPeers := make(map[string]*models.WireguardPeerModel, 0)
	for _, peer := range tunnelPeers {
		if peer.State == models.ProvisionStateProvisioned {
			peer.State = models.ProvisionStateProvisioning
			if _, err := u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				logging.Logger.Errorw(
					"failed to update peer UNPROVISIONING state for tunnel",
					"provider", task.Provider,
					"interface", task.Interface,
					"tunnel", tunnelInfo,
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

	if err := u.deletePeersFromProvider(tunnelInfo, provider, toUnprovisionKeys); err != nil {
		// Flag peers as failed to unprovision
		for _, peer := range toUnprovisionPeers {
			peer.ProvisionStatus = err.Error()
			if _, err := u.wireguardPeersRepository.UpdatePeer(peer); err != nil {
				logging.Logger.Errorw(
					"failed to update peer UNPROVISIONING status for tunnel",
					"provider", task.Provider,
					"interface", task.Interface,
					"tunnel", tunnelInfo,
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
					"provider", task.Provider,
					"interface", task.Interface,
					"tunnel", tunnelInfo,
					"error", err.Error(),
				)
			}
		}
	}
}

func (u *WireguardServiceImpl) handleWireguardDeletionTask(task wireguardDeletionTask) {
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

	u.deletePeerAndIp(task.TunnelInfo, provider, peer)

}

func (u *WireguardServiceImpl) deletePeerAndIp(tunnelInfo *models.WireguardTunnelInfo, provider WireguardTunnelProvider, peers ...*models.WireguardPeerModel) error {
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

func (u *WireguardServiceImpl) deletePeersFromProvider(tunnelInfo *models.WireguardTunnelInfo, provider WireguardTunnelProvider, publicKeys []string) error {
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

	model := &models.WireGuardAggregatedPeerModel{WireguardPeerModel: *peer, Networks: profile.Ranges}

	if iface, found := u.interfaces[tunnel.Provider][tunnel.Interface]; found {
		model.Endpoint = iface.Endpoint
		model.RemotePubKey = iface.PublicKey
	}

	return model, nil
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

func (u *WireguardServiceImpl) getTunnelInfoByInterfaceAndProvider(interfaceName, provider string) *models.WireguardTunnelInfo {
	for _, tunnel := range u.tunnels {
		if tunnel.Provider == provider && tunnel.Interface == interfaceName {
			return &tunnel
		}
	}
	return nil
}
