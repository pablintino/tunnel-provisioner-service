package repositories

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

const (
	peersCollection = "wireguard-peers"
)

type WireguardPeersRepository interface {
	GetPeers(username string) ([]*models.WireguardPeerModel, error)
	GetPeerById(username, id string) (*models.WireguardPeerModel, error)
	SavePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error)
	UpdatePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error)
	DeletePeer(username, id string) (*models.WireguardPeerModel, error)
}

type WireguardPeersRepositoryImpl struct {
	db              *mongo.Database
	peersCollection *mongo.Collection
}

func NewPeersRepositoryImpl(db *mongo.Database) *WireguardPeersRepositoryImpl {
	return &WireguardPeersRepositoryImpl{db: db, peersCollection: db.Collection(peersCollection)}
}

func (r *WireguardPeersRepositoryImpl) SavePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	result, err := r.peersCollection.InsertOne(context.TODO(), peer)
	if err != nil {
		return nil, err
	}
	peer.Id = result.InsertedID.(primitive.ObjectID)
	return peer, nil

}

func (r *WireguardPeersRepositoryImpl) UpdatePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	update := bson.M{
		"$set": peer,
	}
	result, err := r.peersCollection.UpdateByID(context.TODO(), peer.Id, update)
	if err != nil {
		return nil, err
	}
	if result.ModifiedCount != 1 {
		return nil, fmt.Errorf("update of WireguardPeerModel %s failed cause update count is %d", peer.Id.Hex(), result.ModifiedCount)
	}

	return peer, nil
}

func (r *WireguardPeersRepositoryImpl) DeletePeer(username, id string) (*models.WireguardPeerModel, error) {
	mongoId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	result := r.peersCollection.FindOneAndDelete(context.TODO(), bson.M{"_id": mongoId, "username": username})
	if result.Err() == mongo.ErrNoDocuments {
		return nil, result.Err()
	} else if result.Err() != nil {
		return nil, result.Err()
	}
	var wpm models.WireguardPeerModel
	if err := result.Decode(&wpm); err != nil {
		return nil, err
	}
	return &wpm, nil
}

func (r *WireguardPeersRepositoryImpl) GetPeers(username string) ([]*models.WireguardPeerModel, error) {
	cursor, err := r.peersCollection.Find(context.TODO(), bson.D{{Key: "username", Value: username}})
	if err != nil {
		logging.Logger.Errorw(
			"Cannot run Wireguard list query",
			"user", username,
			"error", err,
		)
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var result []*models.WireguardPeerModel
	for cursor.Next(context.TODO()) {
		var wpm models.WireguardPeerModel
		if err := cursor.Decode(&wpm); err != nil {
			return nil, err
		}

		result = append(result, &wpm)
	}

	return result, cursor.Err()
}

func (r *WireguardPeersRepositoryImpl) GetPeerById(username, id string) (*models.WireguardPeerModel, error) {
	mongoId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}
	result := r.peersCollection.FindOne(context.TODO(), bson.M{"_id": mongoId, "username": username})
	if result.Err() == mongo.ErrNoDocuments {
		return nil, nil
	} else if result.Err() != nil {
		return nil, result.Err()
	}
	var wpm models.WireguardPeerModel
	if err := result.Decode(&wpm); err != nil {
		return nil, err
	}
	return &wpm, nil
}
