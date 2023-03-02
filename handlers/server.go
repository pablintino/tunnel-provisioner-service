package handlers

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
)

type EchoServer struct {
	Config                *config.ServiceConfig
	TokenHandler          *TokenHandler
	WireguardPeersHandler *WireguardPeersHandler
	echo                  *echo.Echo
}

func NewEchoServer(
	echo *echo.Echo,
	config *config.ServiceConfig,
	tokenHandler *TokenHandler,
	wireguardPeersHandler *WireguardPeersHandler,
) *EchoServer {
	return &EchoServer{
		echo:                  echo,
		WireguardPeersHandler: wireguardPeersHandler,
		TokenHandler:          tokenHandler,
		Config:                config,
	}
}

func (s *EchoServer) Run() error {
	logging.Logger.Infof("Service started on %d", s.Config.ServicePort)
	if err := s.echo.Start(fmt.Sprintf(":%d", s.Config.ServicePort)); err != http.ErrServerClosed {
		logging.Logger.Errorw(
			"echo failed to boot", "error", err.Error())
		return err
	}
	return nil
}
