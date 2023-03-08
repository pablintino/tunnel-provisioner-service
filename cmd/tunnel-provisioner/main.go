package main

import (
	"os"
	"os/signal"
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

	configuration, err := config.New(opts.ConfigPath)
	if err != nil {
		logging.Logger.Errorw("Error reading service configuration", "error", err)
		return err
	}

	sigIntChan := make(chan os.Signal, 1)
	signal.Notify(sigIntChan, os.Interrupt)

	// Create containers
	securityContainer, err := security.NewContainer(configuration)
	if err != nil {
		logging.Logger.Errorw("Error booting security components", "error", err)
		return err
	}
	reposContainer, err := repositories.NewContainer(securityContainer.TLSCustomCAs, configuration)
	if err != nil {
		return err
	}
	servicesContainer := services.NewContainer(reposContainer, configuration)
	handlersContainer := handlers.NewContainer(servicesContainer, securityContainer, configuration, sigIntChan)
	defer reposContainer.Destroy()
	defer servicesContainer.Destroy()

	// Start boot process
	if err = servicesContainer.Boot(); err == nil {
		err = handlersContainer.EchoServer.Run()
	}

	if err != nil {
		logging.Logger.Errorw("Error booting/running tunnel service", "error", err)
	}

	return err
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
