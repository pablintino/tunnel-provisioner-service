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
	"tunnel-provisioner-service/security"
	"tunnel-provisioner-service/services"
)

func printBanner() {
	logging.Logger.Infof(
		"### Tunnel Provisioner Service (%s) #%s, %d Pablintino",
		config.Version,
		config.SourceVersion,
		config.Year)
	logging.Logger.Infof("Service is starting...")
}

func run() error {
	opts, err := config.ParseRunningOpts()
	if err != nil {
		return err
	}

	logging.Initialize(opts.Verbose)
	defer logging.Release()

	printBanner()

	serviceConfig, err := config.NewServiceConfig(opts.ConfigPath)
	if err != nil {
		logging.Logger.Errorw("Error reading service configuration", "error", err)
		return err
	}
	err = serviceConfig.Validate()
	if err != nil {
		logging.Logger.Errorw("Configuration validation error", "error", err)
		return err
	}

	tlsPools, err := security.NewTlsCertificatePool(serviceConfig.TLS)
	if err != nil {
		logging.Logger.Errorw("Error reading/loading TLS certificates", "error", err)
		return err
	}

	mongoClient, err := repositories.BuildClient(serviceConfig.MongoDBConfiguration)
	if err != nil {
		return err
	}
	defer mongoClient.Disconnect(context.TODO())

	db := mongoClient.Database(serviceConfig.MongoDBConfiguration.Database)

	usersRepository := repositories.NewLDAPUsersRepository(serviceConfig.LDAPConfiguration, tlsPools)
	peersRepository := repositories.NewPeersRepository(db)
	ipPoolRepository := repositories.NewIpPoolRepository(db)
	wireguardInterfacesRepository := repositories.NewWireguardInterfacesRepository(db)

	userService := services.NewUserService(usersRepository)

	providers := services.BuilderProvidersMap(serviceConfig)

	tunnelService := services.NewWireguardTunnelService(
		wireguardInterfacesRepository,
		serviceConfig,
		providers,
	)

	poolService := services.NewPoolService(ipPoolRepository, providers)
	peersService := services.NewWireguardPeersService(
		peersRepository,
		providers,
		poolService,
		tunnelService,
		userService,
	)

	syncService := services.NewWireguardSyncService(peersService, tunnelService, serviceConfig.SyncPeriodMs)

	defer peersService.OnClose()
	defer syncService.OnClose()
	defer services.CloseProviders(providers)

	if err := onWireguardBoot(tunnelService, syncService); err != nil {
		logging.Logger.Errorw("error booting-up wireguard services", "error", err)
		return err
	}

	echoInstance := echo.New()
	echoInstance.HideBanner = true
	echoInstance.HidePort = true
	handlers.Register(echoInstance, userService, peersService, tunnelService)

	logging.Logger.Infof("Service started on %d", serviceConfig.ServicePort)
	if err := echoInstance.Start(fmt.Sprintf(":%d", serviceConfig.ServicePort)); err != http.ErrServerClosed {
		logging.Logger.Errorw(
			"echo failed to boot", "error", err.Error())
	}
	return nil
}

func onWireguardBoot(tunnelService services.WireguardTunnelService, syncService services.WireguardSyncService) error {
	if err := tunnelService.OnBoot(); err != nil {
		return err
	}
	return syncService.OnBoot()
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
