package repositories

import (
	"context"
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
	GetPeers(user string) ([]*models.WireguardPeerModel, error)
	SavePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error)
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

func (r *WireguardPeersRepositoryImpl) GetPeers(user string) ([]*models.WireguardPeerModel, error) {
	cursor, err := r.peersCollection.Find(context.TODO(), bson.D{{Key: "username", Value: user}})
	if err != nil {
		logging.Logger.Errorw(
			"Cannot run Wireguard list query",
			"user", user,
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
