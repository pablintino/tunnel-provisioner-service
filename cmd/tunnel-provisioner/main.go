package main

import (
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
		"### Tunnel Provisioner Service (%s) #%s, Pablintino", config.Version, config.SourceVersion)
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

	// Create containers
	reposContainer, err := repositories.NewContainer(tlsPools, serviceConfig)
	if err != nil {
		return err
	}
	servicesContainer := services.NewContainer(reposContainer, serviceConfig)
	handlersContainer := handlers.NewContainer(servicesContainer, serviceConfig)
	defer reposContainer.Destroy()
	defer servicesContainer.Destroy()

	// Start boot process
	if err = servicesContainer.Boot(); err == nil {
		err = handlersContainer.EchoServer.Run()
	}

	logging.Logger.Sync()

	return err
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
