package handlers

import (
	"github.com/labstack/echo/v4"
	"os"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/security"
	"tunnel-provisioner-service/services"
)

type Container struct {
	tokenHandler *TokenHandler
	peersHandler *WireguardPeersHandler
	EchoServer   *EchoServer
	echoInstance *echo.Echo
}

func NewContainer(servicesContainer *services.Container, securityContainer *security.Container, configuration *config.Config, sigIntChan chan os.Signal,
) *Container {

	echoInstance := newEchoInstance()

	group := echoInstance.Group("/api/v1")

	var tokenHandler *TokenHandler = nil
	if shouldEnableTokenHandler(&configuration.Security.JWT) {
		tokenHandler = NewTokenHandler(group, servicesContainer.UsersService, securityContainer.JwtTokenEncoder)
	}

	peersHandler := NewWireguardPeersHandler(group, servicesContainer.PeersService, servicesContainer.TunnelService,
		NewEchoJwtMiddlewareFactory(securityContainer.JwtTokenDecoder))
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

func shouldEnableTokenHandler(jwtConfig *config.JWTConfiguration) bool {
	// Token handler is only available if no other method of verifying is loaded (random or loaded key will be used)
	return jwtConfig.JWTValidationKey == "" && jwtConfig.JWKSUrl == ""
}
