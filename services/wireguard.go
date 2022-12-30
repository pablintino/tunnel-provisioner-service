package services

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

type WireguardService interface {
	ListPeers(username string) ([]*models.WireguardPeerModel, error)
	CreatePeer(username, tunnelId, profileId string, description, psk *string) (*models.WireguardPeerModel, error)
	GetTunnels() []*models.WireguardTunnelInfo
	GetTunnelInfo(tunnelId string) *models.WireguardTunnelInfo
	GetProfileInfo(tunnelId, profileId string) *models.WireguardTunnelProfileInfo
}

type WireguardServiceImpl struct {
	wireguardPeersRepository repositories.WireguardPeersRepository
	taskChannel              chan interface{}
	tunnels                  map[string]models.WireguardTunnelInfo
}

type wireguardCreationTask struct {
	Psk         *string
	Description *string
	Username    string
	TaskId      string
	Ranges      []net.IPNet
}

func NewWireguardService(wireguardPeersRepository repositories.WireguardPeersRepository, config *config.ServiceConfig) (*WireguardServiceImpl, error) {

	taskChannel := make(chan interface{}, 128)

	wireguardService := &WireguardServiceImpl{
		wireguardPeersRepository: wireguardPeersRepository,
		taskChannel:              taskChannel,
		tunnels:                  make(map[string]models.WireguardTunnelInfo),
	}
	wireguardService.buildTunnelInfo(config)

	return wireguardService, nil
}

func (u *WireguardServiceImpl) ListPeers(username string) ([]*models.WireguardPeerModel, error) {
	return u.wireguardPeersRepository.GetPeers(username)
}

func (u *WireguardServiceImpl) CreatePeer(username, tunnelId, profileId string, description, psk *string) (*models.WireguardPeerModel, error) {

	profile, profileFound := u.tunnels[tunnelId].Profiles[profileId]
	if !profileFound {
		return nil, errors.New(fmt.Sprintf("Profile %s not for tunnel %s found", profileId, tunnelId))
	}

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
		Psk:         psk,
		Description: description,
		Username:    username,
		TaskId:      peer.Id.Hex(),
		Ranges:      profile.Ranges,
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

func (u *WireguardServiceImpl) wireguardSyncRoutine() {
	p := <-u.taskChannel
	switch p := p.(type) {

	default:
		fmt.Printf("Type of p is %T. Value %v", p, p)
	}
}

func (u *WireguardServiceImpl) buildTunnelInfo(config *config.ServiceConfig) {
	for _, provider := range config.Providers.RouterOS {
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
				Id:       tunnelId,
				Name:     tunnelName,
				Provider: models.ProviderTypeRouterOS,
				Profiles: profiles,
			}

		}
	}
}

func appendProfileRange(networkRange string, ranges []net.IPNet) []net.IPNet {
	// Ignore error as config was validated before and ranges are parseable at this point
	_, netRange, _ := net.ParseCIDR(networkRange)

	for _, rangeAt := range ranges {
		if netRange.IP.Equal(rangeAt.IP) && bytes.Compare((*netRange).Mask, rangeAt.Mask) == 0 {
			return ranges
		}
	}

	return append(ranges, *netRange)
}
