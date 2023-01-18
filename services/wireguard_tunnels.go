package services

import (
	"bytes"
	"errors"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"net"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/utils"
)

const (
	interfaceResolutionPeriod = 1 * time.Hour
)

type OnTunnelInterfaceDown func(tunnelInfo models.WireguardTunnelInfo, deleted bool)
type OnTunnelConfigurationChange func(tunnelInfo models.WireguardTunnelInfo, keyChanged, endpointChanged bool)

type WireguardTunnelService interface {
	BooteableService
	DisposableService
	GetTunnels() []models.WireguardTunnelInfo
	GetTunnelInfo(tunnelId string) (models.WireguardTunnelInfo, error)
	GetProfileInfo(tunnelId, profileId string) (models.WireguardTunnelProfileInfo, error)
	GetTunnelConfigById(tunnelId, profileId string) (models.WireguardTunnelInfo, models.WireguardTunnelProfileInfo, error)
	SetTunnelDownCallback(cb OnTunnelInterfaceDown)
	SetTunnelConfigurationChangeCallback(cb OnTunnelConfigurationChange)
}

type WireguardTunnelServiceImpl struct {
	interfacesRepository     repositories.WireguardInterfacesRepository
	tunnels                  map[string]*models.WireguardTunnelInfo
	providers                map[string]WireguardTunnelProvider
	config                   *config.ServiceConfig
	interfaceResolutionTimer *time.Ticker
	tunnelDownCallback       OnTunnelInterfaceDown
	tunnelInfoChangeCallback OnTunnelConfigurationChange
	notificationService      NotificationService
}

func NewWireguardTunnelService(interfacesRepository repositories.WireguardInterfacesRepository, config *config.ServiceConfig,
	providers map[string]WireguardTunnelProvider, notificationService NotificationService) *WireguardTunnelServiceImpl {
	tunnelService := &WireguardTunnelServiceImpl{
		interfacesRepository: interfacesRepository,
		tunnels:              make(map[string]*models.WireguardTunnelInfo),
		providers:            providers,
		config:               config,
		notificationService:  notificationService,
	}

	tunnelService.buildTunnelInfo(config)

	return tunnelService
}

func (s *WireguardTunnelServiceImpl) SetTunnelDownCallback(cb OnTunnelInterfaceDown) {
	s.tunnelDownCallback = cb
}

func (s *WireguardTunnelServiceImpl) SetTunnelConfigurationChangeCallback(cb OnTunnelConfigurationChange) {
	s.tunnelInfoChangeCallback = cb
}

func (s *WireguardTunnelServiceImpl) GetTunnels() []models.WireguardTunnelInfo {
	tunnels := make([]models.WireguardTunnelInfo, 0)
	for _, v := range s.tunnels {
		tunnels = append(tunnels, *v)
	}
	return tunnels
}

func (s *WireguardTunnelServiceImpl) OnClose() error {
	if s.interfaceResolutionTimer != nil {
		s.interfaceResolutionTimer.Stop()
	}
	return nil
}

func (s *WireguardTunnelServiceImpl) OnBoot() error {
	// Load interfaces from DB at first
	s.loadAndCleanTunnelInterfaces()

	s.refreshTunnelInterfacesInformation()

	if s.interfaceResolutionTimer == nil {
		s.interfaceResolutionTimer = time.NewTicker(interfaceResolutionPeriod)

		// Launch interface resolution as a routine
		go s.refreshTunnelsInterfacesInformationRoutine()
	}

	return nil
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

func (s *WireguardTunnelServiceImpl) refreshTunnelInterfacesInformation() {
	for _, tunnel := range s.tunnels {
		interfaceResolutionData, err := s.providers[tunnel.Provider].GetTunnelInterfaceInfo(tunnel.Interface.Name)
		deleted := err != nil && errors.Is(err, ErrProviderInterfaceNotFound)
		if deleted || !interfaceResolutionData.Enabled {
			// Interface miss-configured or deleted/disabled at provider, trigger unprovision
			if s.tunnelDownCallback != nil {
				s.tunnelDownCallback(*tunnel, deleted)
			}
		} else if err != nil {
			logging.Logger.Errorw(
				"Error retrieving tunnel resolution data",
				"tunnel", tunnel.Name,
				"interface", tunnel.Interface.Name,
			)
		}

		if err == nil {

			// If interface already exists and an actual change exists
			if tunnel.Interface.Id != primitive.NilObjectID &&
				(tunnel.Interface.PublicKey != interfaceResolutionData.PublicKey ||
					tunnel.Interface.Endpoint != interfaceResolutionData.Endpoint) {

				tunnel.Interface.PublicKey = interfaceResolutionData.PublicKey
				tunnel.Interface.Endpoint = interfaceResolutionData.Endpoint

				// Notify the other services about the change
				if s.tunnelInfoChangeCallback != nil {
					s.tunnelInfoChangeCallback(
						*tunnel,
						tunnel.Interface.PublicKey != interfaceResolutionData.PublicKey,
						tunnel.Interface.Endpoint != interfaceResolutionData.Endpoint,
					)
				}

				// Persist the change in DB
				if _, err := s.interfacesRepository.Update(&tunnel.Interface); err != nil {
					logging.Logger.Errorw(
						"Error updating interface change in DB",
						"provider", tunnel.Provider,
						"interface", tunnel.Interface.Name,
						"err", err.Error(),
					)
				}
			} else if tunnel.Interface.Id == primitive.NilObjectID {
				// New iface....
				tunnel.Interface.PublicKey = interfaceResolutionData.PublicKey
				tunnel.Interface.Endpoint = interfaceResolutionData.Endpoint
				if _, err := s.interfacesRepository.Save(&tunnel.Interface); err != nil {
					logging.Logger.Errorw(
						"Error persisting a new interface in DB",
						"provider", tunnel.Provider,
						"interface", tunnel.Interface.Name,
						"err", err.Error(),
					)
				}
			}
		}
	}
}

func (s *WireguardTunnelServiceImpl) loadAndCleanTunnelInterfaces() {
	dbInterfaces, err := s.interfacesRepository.GetAll()
	if err != nil {
		logging.Logger.Errorw(
			"Error cleaning tunnel interfaces",
			"err", err.Error(),
		)
		return
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
			}
		}
	}
}

func (s *WireguardTunnelServiceImpl) buildTunnelInfo(config *config.ServiceConfig) {
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
			s.tunnels[tunnelId] = &models.WireguardTunnelInfo{
				Id:        tunnelId,
				Name:      tunnelName,
				Provider:  providerName,
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

func (s *WireguardTunnelServiceImpl) refreshTunnelsInterfacesInformationRoutine() {
	for {
		select {
		case _, ok := <-s.interfaceResolutionTimer.C:
			if !ok {
				logging.Logger.Debug("Exiting the refreshTunnelsInterfacesInformationRoutine")
				return
			}
		}
		s.refreshTunnelInterfacesInformation()
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
