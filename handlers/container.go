package handlers

import (
	"github.com/labstack/echo/v4"
	"os"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/services"
)

type Container struct {
	tokenHandler *TokenHandler
	peersHandler *WireguardPeersHandler
	EchoServer   *EchoServer
	echoInstance *echo.Echo
}

func NewContainer(servicesContainer *services.Container, configuration *config.Config, sigIntChan chan os.Signal,
) *Container {

	echoInstance := newEchoInstance()

	group := echoInstance.Group("/api/v1")

	tokenHandler := NewTokenHandler(group, servicesContainer.UsersService, &configuration.Security.JWT)
	peersHandler := NewWireguardPeersHandler(group, servicesContainer.PeersService, servicesContainer.TunnelService, &configuration.Security.JWT)
	return &Container{
		echoInstance: echoInstance,
		tokenHandler: tokenHandler,
		peersHandler: peersHandler,
		EchoServer:   NewEchoServer(echoInstance, configuration, tokenHandler, peersHandler, sigIntChan),
	}
}

func newEchoInstance() *echo.Echo {
	echoInstance := echo.New()
	echoInstance.HideBanner = true
	echoInstance.HidePort = true
	return echoInstance
}
