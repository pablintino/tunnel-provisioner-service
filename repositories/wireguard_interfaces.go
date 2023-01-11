package repositories

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"tunnel-provisioner-service/models"
)

const (
	wireguardInterfacesCollection = "wireguard-interfaces"
)

type WireguardInterfacesRepository interface {
	RemoveAll(provider string) error
	GetProviderInterfaces(provider string) ([]*models.WireguardInterfaceModel, error)
	Save(iface *models.WireguardInterfaceModel) (*models.WireguardInterfaceModel, error)
}

type WireguardInterfacesRepositoryImpl struct {
	db                            *mongo.Database
	wireguardInterfacesCollection *mongo.Collection
}

func NewWireguardInterfacesRepository(db *mongo.Database) *WireguardInterfacesRepositoryImpl {
	return &WireguardInterfacesRepositoryImpl{db: db, wireguardInterfacesCollection: db.Collection(wireguardInterfacesCollection)}
}

func (r *WireguardInterfacesRepositoryImpl) Save(iface *models.WireguardInterfaceModel) (*models.WireguardInterfaceModel, error) {
	result, err := r.wireguardInterfacesCollection.InsertOne(context.TODO(), iface)
	if err != nil {
		return nil, err
	}
	iface.Id = result.InsertedID.(primitive.ObjectID)
	return iface, nil
}

func (r *WireguardInterfacesRepositoryImpl) RemoveAll(provider string) error {
	_, err := r.wireguardInterfacesCollection.DeleteMany(context.TODO(), bson.D{{Key: "provider", Value: provider}})
	return err
}

func (r *WireguardInterfacesRepositoryImpl) GetProviderInterfaces(provider string) ([]*models.WireguardInterfaceModel, error) {
	cursor, err := r.wireguardInterfacesCollection.Find(context.TODO(), bson.D{{Key: "provider", Value: provider}})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var result []*models.WireguardInterfaceModel
	for cursor.Next(context.TODO()) {
		var wpm models.WireguardInterfaceModel
		if err := cursor.Decode(&wpm); err != nil {
			return nil, err
		}

		result = append(result, &wpm)
	}

	return result, cursor.Err()
}
