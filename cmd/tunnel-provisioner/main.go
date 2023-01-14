package main

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	"net/http"
	"os"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/handlers"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/services"
)

func run() error {
	echoInstance := echo.New()

	logging.Initialize(config.GetDebugMode())
	defer logging.Release()

	var serviceConfig config.ServiceConfig
	err := config.LoadConfig(&serviceConfig)
	if err != nil {
		logging.Logger.Errorw("Error reading service configuration", "error", err)
		return err
	}
	err = serviceConfig.Validate()
	if err != nil {
		logging.Logger.Errorw("Configuration validation error", "error", err)
		return err
	}

	mongoClient, err := repositories.BuildClient(serviceConfig.MongoDBConfiguration)
	if err != nil {
		return err
	}
	defer mongoClient.Disconnect(context.TODO())

	db := mongoClient.Database(serviceConfig.MongoDBConfiguration.Database)

	usersRepository := repositories.NewLDAPUsersRepository(serviceConfig.LDAPConfiguration)
	peersRepository := repositories.NewPeersRepository(db)
	ipPoolRepository := repositories.NewIpPoolRepository(db)
	wireguardInterfacesRepository := repositories.NewWireguardInterfacesRepository(db)

	userService := services.NewUserService(usersRepository)

	providers := services.BuilderProvidersMap(&serviceConfig)
	defer services.CloseProviders(providers)

	poolService := services.NewPoolService(ipPoolRepository, providers)
	wireguardService := services.NewWireguardService(peersRepository, wireguardInterfacesRepository, &serviceConfig, providers, poolService)

	defer wireguardService.Close()

	if err := onWireguardBoot(providers, wireguardService); err != nil {
		logging.Logger.Errorw("error booting-up wireguard services", "error", err)
		return err
	}

	handlers.Register(echoInstance, userService, wireguardService)

	if err := echoInstance.Start(fmt.Sprintf(":%d", serviceConfig.ServicePort)); err != http.ErrServerClosed {
		logging.Logger.Errorw(
			"echo failed to boot", "error", err.Error())
	}
	return nil
}

func onWireguardBoot(wireguardProviders map[string]services.WireguardTunnelProvider, wireguardService services.WireguardService) error {
	// Start booting up from bottom (providers) to top (services)
	for _, provider := range wireguardProviders {
		if err := provider.OnBoot(); err != nil {
			return err
		}
	}
	return wireguardService.OnBoot()
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
