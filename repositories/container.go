package repositories

import (
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/security"
)

type Container struct {
	IpPoolRepository     IpPoolRepository
	UsersRepository      UsersRepository
	InterfacesRepository WireguardInterfacesRepository
	PeersRepository      WireguardPeersRepository
	mongoClient          *mongo.Client
}

func NewContainer(tlsPools *security.TLSCertificatePool, serviceConfig *config.ServiceConfig) (*Container, error) {
	mongoClient, err := BuildClient(serviceConfig.MongoDBConfiguration)
	if err != nil {
		return nil, err
	}

	db := mongoClient.Database(serviceConfig.MongoDBConfiguration.Database)
	return &Container{
		IpPoolRepository:     NewIpPoolRepository(db),
		UsersRepository:      NewLDAPUsersRepository(&serviceConfig.LDAPConfiguration, tlsPools),
		InterfacesRepository: NewWireguardInterfacesRepository(db),
		PeersRepository:      NewPeersRepository(db),
		mongoClient:          mongoClient,
	}, nil
}

func (c *Container) Destroy() {
	c.mongoClient.Disconnect(context.TODO())
}
