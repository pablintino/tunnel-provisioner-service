package repositories

import (
	"context"
	"crypto/x509"
	"go.mongodb.org/mongo-driver/mongo"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
)

type Container struct {
	IpPoolRepository     IpPoolRepository
	UsersRepository      UsersRepository
	InterfacesRepository WireguardInterfacesRepository
	PeersRepository      WireguardPeersRepository
	mongoClient          *mongo.Client
}

func NewContainer(tlsCustomCAs *x509.CertPool, configuration *config.Config) (*Container, error) {
	mongoClient, err := BuildClient(configuration.MongoDBConfiguration)
	if err != nil {
		return nil, err
	}

	db := mongoClient.Database(configuration.MongoDBConfiguration.Database)
	return &Container{
		IpPoolRepository:     NewIpPoolRepository(db),
		UsersRepository:      NewLDAPUsersRepository(&configuration.LDAPConfiguration, tlsCustomCAs),
		InterfacesRepository: NewWireguardInterfacesRepository(db),
		PeersRepository:      NewPeersRepository(db),
		mongoClient:          mongoClient,
	}, nil
}

func (c *Container) Destroy() {
	if err := c.mongoClient.Disconnect(context.TODO()); err != nil {
		logging.Logger.Errorw("Mongo Client disconnect failed ", "error", err)
	}
}
