package main

import (
	"context"
	"fmt"
	"net/http"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/handlers"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/repositories"
	"tunnel-provisioner-service/services"

	"github.com/labstack/echo/v4"
)

func main() {

	echoInstance := echo.New()

	logging.Initialize(config.GetDebugMode())
	defer logging.Release()

	var serviceConfig config.ServiceConfig
	err := config.LoadConfig(&serviceConfig)
	if err != nil {
		logging.Logger.Errorw("Error reading service configuration", "error", err)
		return
	}
	err = serviceConfig.Validate()
	if err != nil {
		logging.Logger.Errorw("Configuration validation error", "error", err)
		return
	}

	mongoClient, err := repositories.BuildClient(serviceConfig.MongoDBConfiguration)
	if err != nil {
		return
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

	handlers.Register(echoInstance, userService, wireguardService)

	if err := echoInstance.Start(fmt.Sprintf(":%d", serviceConfig.ServicePort)); err != http.ErrServerClosed {
		logging.Logger.Errorw(
			"echo failed to boot", "error", err.Error())
	}
}
