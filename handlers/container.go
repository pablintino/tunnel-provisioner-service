package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

	// TODO Remove from here
	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte("secret"),
		Claims:     &jwt.StandardClaims{},
	})

	tokenHandler := NewTokenHandler(group, servicesContainer.UsersService)
	peersHandler := NewWireguardPeersHandler(group, servicesContainer.PeersService, servicesContainer.TunnelService, jwtMiddleware)
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
