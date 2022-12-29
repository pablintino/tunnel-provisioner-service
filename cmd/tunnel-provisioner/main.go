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
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	// Connect to MongoDB
	mongoconn := options.Client().ApplyURI(serviceConfig.MongoDBConfiguration.MongoURI)
	mongoclient, err := mongo.Connect(context.TODO(), mongoconn)
	if err != nil {
		logging.Logger.Errorw("Error configuring/connecting to MongoDB", "error", err)
		return
	}

	defer mongoclient.Disconnect(context.TODO())

	db := mongoclient.Database(serviceConfig.MongoDBConfiguration.Database)

	usersRepository := repositories.NewLDAPUsersRepository(serviceConfig.LDAPConfiguration)
	peersRepository := repositories.NewPeersRepositoryImpl(db)

	userService := services.NewUserService(usersRepository)
	wireguardService := services.NewWireguardService(peersRepository)

	handlers.Register(echo, userService, wireguardService)

	if err := echo.Start(fmt.Sprintf(":%d", serviceConfig.ServicePort)); err != http.ErrServerClosed {
		fmt.Println(err.Error())
	}
}
