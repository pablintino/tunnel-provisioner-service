package services

import (
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

type OnTunnelInterfaceDown func(tunnelInfo models.WireguardTunnelInfo, deleted bool)
type OnTunnelConfigurationChange func(tunnelInfo models.WireguardTunnelInfo, keyChanged, endpointChanged bool)

type WireguardTunnelService interface {
	BooteableService
	GetTunnels() map[string]models.WireguardTunnelInfo
	GetTunnelInfo(tunnelId string) (models.WireguardTunnelInfo, error)
	GetProfileInfo(tunnelId, profileId string) (models.WireguardTunnelProfileInfo, error)
	GetTunnelConfigById(tunnelId, profileId string) (models.WireguardTunnelInfo, models.WireguardTunnelProfileInfo, error)
	RefreshTunnelInterfacesInformation() error
}

type WireguardTunnelServiceImpl struct {
	interfacesRepository repositories.WireguardInterfacesRepository
	tunnels              map[string]*models.WireguardTunnelInfo
	providers            map[string]WireguardTunnelProvider
	config               *config.Config
}

func NewWireguardTunnelService(interfacesRepository repositories.WireguardInterfacesRepository, config *config.Config,
	providers map[string]WireguardTunnelProvider) *WireguardTunnelServiceImpl {
	tunnelService := &WireguardTunnelServiceImpl{
		interfacesRepository: interfacesRepository,
		tunnels:              make(map[string]*models.WireguardTunnelInfo),
		providers:            providers,
		config:               config,
	}

	tunnelService.buildTunnelInfo(config)

	return tunnelService
}

func (s *WireguardTunnelServiceImpl) GetTunnels() map[string]models.WireguardTunnelInfo {
	tunnels := make(map[string]models.WireguardTunnelInfo, 0)
	for k, v := range s.tunnels {
		tunnels[k] = *v
	}
	return tunnels
}

func (s *WireguardTunnelServiceImpl) GetTunnelInfo(tunnelId string) (models.WireguardTunnelInfo, error) {
	if tunnel, ok := s.tunnels[tunnelId]; ok {
		return *tunnel, nil
	}
	return models.WireguardTunnelInfo{}, ErrServiceNotFoundEntity
}

func (s *WireguardTunnelServiceImpl) GetProfileInfo(tunnelId, profileId string) (models.WireguardTunnelProfileInfo, error) {
	if profile, ok := s.tunnels[tunnelId].Profiles[profileId]; ok {
		return profile, nil
	}
	return models.WireguardTunnelProfileInfo{}, ErrServiceNotFoundEntity
}

func (s *WireguardTunnelServiceImpl) GetTunnelConfigById(tunnelId, profileId string) (models.WireguardTunnelInfo, models.WireguardTunnelProfileInfo, error) {
	if profile, ok := s.tunnels[tunnelId].Profiles[profileId]; !ok {
		return models.WireguardTunnelInfo{}, models.WireguardTunnelProfileInfo{}, ErrServiceNotFoundEntity
	} else {
		tunnel := s.tunnels[tunnelId]
		return *tunnel, profile, nil
	}
}

func (s *WireguardTunnelServiceImpl) RefreshTunnelInterfacesInformation() error {
	for _, tunnel := range s.tunnels {
		interfaceResolutionData, err := s.providers[tunnel.Provider].GetTunnelInterfaceInfo(tunnel.Interface.Name)

		if err != nil && !errors.Is(err, ErrProviderInterfaceNotFound) {
			return err
		}

		interfaceChanged := s.fillInterfaceFromRemote(interfaceResolutionData, tunnel)
		// If interface already exists and an actual change exists
		if tunnel.Interface.Id != primitive.NilObjectID && interfaceChanged {
			// Persist the change in DB
			if _, err := s.interfacesRepository.Update(&tunnel.Interface); err != nil {
				logging.Logger.Errorw(
					"Error updating interface change in DB",
					"provider", tunnel.Provider,
					"interface", tunnel.Interface.Name,
					"err", err.Error(),
				)
				return err
			}
		} else if tunnel.Interface.Id == primitive.NilObjectID {
			// New iface....
			if _, err := s.interfacesRepository.Save(&tunnel.Interface); err != nil {
				logging.Logger.Errorw(
					"Error persisting a new interface in DB",
					"provider", tunnel.Provider,
					"interface", tunnel.Interface.Name,
					"err", err.Error(),
				)
				return err
			}
		}
	}
	return nil
}

func (s *WireguardTunnelServiceImpl) fillInterfaceFromRemote(interfaceResolutionData *WireguardInterfaceInfo, tunnel *models.WireguardTunnelInfo) bool {
	interfacePresent := interfaceResolutionData != nil && interfaceResolutionData.Enabled
	interfaceChanged :=
		// Interface status changed
		(tunnel.Interface.Present != interfacePresent) ||
			// Interface status stills match but endpoint and key may have changed
			(interfacePresent &&
				(tunnel.Interface.PublicKey != interfaceResolutionData.PublicKey ||
					tunnel.Interface.Endpoint != interfaceResolutionData.Endpoint || !tunnel.Interface.Present))

	if interfaceChanged {
		if interfacePresent {
			tunnel.Interface.PublicKey = interfaceResolutionData.PublicKey
			tunnel.Interface.Endpoint = interfaceResolutionData.Endpoint
		} else {
			tunnel.Interface.PublicKey = ""
			tunnel.Interface.Endpoint = ""
		}
		tunnel.Interface.Present = interfacePresent
	}
	return interfaceChanged
}

func (s *WireguardTunnelServiceImpl) OnBoot() error {
	dbInterfaces, err := s.interfacesRepository.GetAll()
	if err != nil {
		logging.Logger.Errorw(
			"Error cleaning tunnel interfaces",
			"err", err.Error(),
		)
		return err
	}

	for _, interfaceModel := range dbInterfaces {
		if interfaceTunnel := s.getTunnelForInterface(interfaceModel); interfaceTunnel != nil {
			s.tunnels[interfaceTunnel.Id].Interface = *interfaceModel
		} else {
			// Cleanup unused interfaces
			if err := s.interfacesRepository.DeleteInterface(interfaceModel); err != nil {
				logging.Logger.Errorw(
					"Error while deleting interface in DB",
					"interface", interfaceModel,
					"err", err.Error(),
				)
				return err
			}
		}
	}
	return nil
}

func (s *WireguardTunnelServiceImpl) buildTunnelInfo(config *config.Config) {
	for providerName, provider := range config.Providers.RouterOS {
		for tunnelName, tunnelConfig := range provider.WireguardTunnels {
			profiles := make(map[string]models.WireguardTunnelProfileInfo, 0)
			for profName, profile := range tunnelConfig.Profiles {
				profileId := utils.GenerateInternalIdFromString(profName)
				profiles[profileId] = models.WireguardTunnelProfileInfo{
					Name:   profName,
					Ranges: utils.TryParseNetSlice(profile.Ranges), // Safe as validated on boot
					Id:     profileId,
				}
			}

			tunnelId := utils.GenerateInternalIdFromString(tunnelName)
			s.tunnels[tunnelId] = &models.WireguardTunnelInfo{
				Id:        tunnelId,
				Name:      tunnelName,
				Provider:  providerName,
				DNSs:      utils.TryParseIPSlice(tunnelConfig.DNSs), // Safe as validated on boot
				Interface: models.WireguardInterfaceModel{Name: tunnelConfig.Interface, Provider: providerName},
				Profiles:  profiles,
			}
		}
	}
}

func (s *WireguardTunnelServiceImpl) getTunnelForInterface(interfaceModel *models.WireguardInterfaceModel) *models.WireguardTunnelInfo {
	for _, tunnel := range s.tunnels {
		if tunnel.Provider == interfaceModel.Provider && tunnel.Interface.Name == interfaceModel.Name {
			return tunnel
		}
	}
	return nil
}
