package services

import (
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/repositories"
)

type Container struct {
	TunnelService WireguardTunnelService
	PoolService   PoolService
	PeersService  WireguardPeersService
	UsersService  UsersService
	qrEncoder     WireguardQrEncoder
	providers     map[string]WireguardTunnelProvider
	syncService   WireguardSyncService
}

func NewContainer(reposContainer *repositories.Container, serviceConfig *config.ServiceConfig) *Container {
	providers := BuilderProvidersMap(serviceConfig)
	qrEncoder := NewWireguardQrEncoder()
	tunnelService := NewWireguardTunnelService(reposContainer.InterfacesRepository, serviceConfig, providers)
	poolService := NewPoolService(reposContainer.IpPoolRepository, providers)
	userService := NewUserService(reposContainer.UsersRepository)
	peersService := NewWireguardPeersService(reposContainer.PeersRepository, providers, poolService, tunnelService, userService, qrEncoder)
	syncService := NewWireguardSyncService(peersService, tunnelService, serviceConfig.SyncPeriodMs)
	return &Container{
		TunnelService: tunnelService,
		PoolService:   poolService,
		PeersService:  peersService,
		UsersService:  userService,
		qrEncoder:     qrEncoder,
		providers:     providers,
		syncService:   syncService,
	}
}

func (c *Container) Boot() error {
	if err := c.TunnelService.OnBoot(); err != nil {
		return err
	}
	return c.syncService.OnBoot()
}

func (c *Container) Destroy() {
	c.PeersService.OnClose()
	c.syncService.OnClose()
	for _, provider := range c.providers {
		provider.OnClose()
	}
}
