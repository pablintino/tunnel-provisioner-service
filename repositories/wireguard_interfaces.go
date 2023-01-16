package repositories

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"tunnel-provisioner-service/models"
)

const (
	wireguardInterfacesCollection = "wireguard-interfaces"
)

type WireguardInterfacesRepository interface {
	DeleteInterface(interfaceModel *models.WireguardInterfaceModel) error
	GetAll() ([]*models.WireguardInterfaceModel, error)
	Update(interfaceModel *models.WireguardInterfaceModel) (*models.WireguardInterfaceModel, error)
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

func (r *WireguardInterfacesRepositoryImpl) DeleteInterface(interfaceModel *models.WireguardInterfaceModel) error {
	_, err := r.wireguardInterfacesCollection.DeleteOne(context.TODO(), bson.M{"_id": interfaceModel.Id})
	return err
}

func (r *WireguardInterfacesRepositoryImpl) Update(
	interfaceModel *models.WireguardInterfaceModel,
) (*models.WireguardInterfaceModel, error) {
	update := bson.M{
		"$set": interfaceModel,
	}
	result, err := r.wireguardInterfacesCollection.UpdateByID(context.TODO(), interfaceModel.Id, update)
	if err != nil {
		return nil, err
	}

	if result.ModifiedCount != 1 {
		return nil, fmt.Errorf("update of WireguardInterfaceModel %s failed cause update count is %d", interfaceModel.Id.Hex(), result.ModifiedCount)
	}

	return interfaceModel, nil
}

func (r *WireguardInterfacesRepositoryImpl) GetAll() ([]*models.WireguardInterfaceModel, error) {
	cursor, err := r.wireguardInterfacesCollection.Find(context.TODO(), bson.D{})
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
