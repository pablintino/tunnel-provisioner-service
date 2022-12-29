package services

import (
	"encoding/hex"
	"fmt"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
)

type WireguardService interface {
	ListPeers(username string) ([]*models.WireguardPeerModel, error)
	CreatePeer(username string, description, psk *string) (*models.WireguardPeerModel, error)
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
}

func NewWireguardService(wireguardPeersRepository repositories.WireguardPeersRepository) *WireguardServiceImpl {

	taskChannel := make(chan interface{}, 0)

	return &WireguardServiceImpl{wireguardPeersRepository: wireguardPeersRepository, taskChannel: taskChannel}
}

func (u *WireguardServiceImpl) ListPeers(username string) ([]*models.WireguardPeerModel, error) {
	return u.wireguardPeersRepository.GetPeers(username)
}

func (u *WireguardServiceImpl) CreatePeer(username string, description, psk *string) (*models.WireguardPeerModel, error) {
	peer := &models.WireguardPeerModel{Username: username, Description: description, PresharedKey: psk, State: models.ProvisionStateProvisioning, CreationTime: time.Now()}

	err := u.wireguardPeersRepository.SavePeer(peer)
	if err != nil {
		return nil, err
	}

	creationTask := wireguardCreationTask{
		Psk:         psk,
		Description: description,
		Username:    username,
		TaskId:      peer.Id.Hex(),
	}
	u.taskChannel <- creationTask

	return peer, nil
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

			for profName, prof := range tunnelConfig.Profiles {

			}

			u.tunnels[tunnelName] = models.WireguardTunnelInfo{
				Id:       hex.EncodeToString([]byte(tunnelName)),
				Name:     tunnelName,
				Provider: models.ProviderTypeRouterOS,
			}

		}

	}
}
