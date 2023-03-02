package main

import (
	"crypto/x509"
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

	var tlsCustomCAs *x509.CertPool
	if configuration.Security.CustomCAsPath != "" {
		tlsCustomCAs, err = security.NewTLSCustomCAs(configuration.Security.CustomCAsPath)
		if err != nil {
			logging.Logger.Errorw("Error reading/loading TLS certificates", "error", err)
			return err
		}
	}

	sigIntChan := make(chan os.Signal, 1)
	signal.Notify(sigIntChan, os.Interrupt)

	// Create containers
	reposContainer, err := repositories.NewContainer(tlsCustomCAs, configuration)
	if err != nil {
		return err
	}
	servicesContainer := services.NewContainer(reposContainer, configuration)
	handlersContainer := handlers.NewContainer(servicesContainer, configuration, sigIntChan)
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
