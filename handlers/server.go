package handlers

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"os"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
)

type EchoServer struct {
	Config                *config.Config
	TokenHandler          *TokenHandler
	WireguardPeersHandler *WireguardPeersHandler
	echo                  *echo.Echo
	serverErrChan         chan error
	sigIntChan            chan os.Signal
}

func NewEchoServer(
	echo *echo.Echo,
	config *config.Config,
	tokenHandler *TokenHandler,
	wireguardPeersHandler *WireguardPeersHandler,
	sigIntChan chan os.Signal,
) *EchoServer {
	return &EchoServer{
		echo:                  echo,
		WireguardPeersHandler: wireguardPeersHandler,
		TokenHandler:          tokenHandler,
		Config:                config,
		serverErrChan:         make(chan error, 1),
		sigIntChan:            sigIntChan,
	}
}

func (s *EchoServer) serverRun() {
	go func() {
		logging.Logger.Infof("Service started on %d", s.Config.ServicePort)
		if err := s.echo.Start(fmt.Sprintf(":%d", s.Config.ServicePort)); err != http.ErrServerClosed {
			s.serverErrChan <- err
		}
	}()
}

func (s *EchoServer) Run() error {
	s.serverRun()

	select {
	case <-s.sigIntChan:
		return s.shutdownEchoInstance()
	case err := <-s.serverErrChan:
		return err
	}
}

func (s *EchoServer) shutdownEchoInstance() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.echo.Shutdown(ctx)
}
