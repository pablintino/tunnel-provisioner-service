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

	echo := echo.New()

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

	userService := services.NewUserService(usersRepository)

	providers := services.BuilderProvidersMap(&serviceConfig)
	defer services.CloseProviders(providers)

	poolService := services.NewPoolService(ipPoolRepository, providers)
	wireguardService, err := services.NewWireguardService(peersRepository, &serviceConfig, providers, poolService)
	if err != nil {
		logging.Logger.Errorw("Error configuring/connecting to MongoDB", "error", err)
		return
	}

	defer wireguardService.Close()

	handlers.Register(echo, userService, wireguardService)

	if err := echo.Start(fmt.Sprintf(":%d", serviceConfig.ServicePort)); err != http.ErrServerClosed {
		fmt.Println(err.Error())
	}
}
