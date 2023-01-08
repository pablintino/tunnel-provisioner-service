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
	ipPoolCollection = "ip-pools"
)

type IpPoolRepository interface {
	GetPool(provider, tunnel string) (*models.IpPoolModel, error)
	SavePool(ipPool *models.IpPoolModel) (*models.IpPoolModel, error)
	UpdatePool(ipPool *models.IpPoolModel) (*models.IpPoolModel, error)
}

type IpPoolRepositoryImpl struct {
	db               *mongo.Database
	ipPoolCollection *mongo.Collection
}

func NewIpPoolRepository(db *mongo.Database) *IpPoolRepositoryImpl {
	return &IpPoolRepositoryImpl{db: db, ipPoolCollection: db.Collection(ipPoolCollection)}
}

func (r *IpPoolRepositoryImpl) GetPool(provider, tunnel string) (*models.IpPoolModel, error) {
	result := r.ipPoolCollection.FindOne(context.TODO(), bson.M{"provider": provider, "tunnel": tunnel})
	if result.Err() == mongo.ErrNoDocuments {
		return nil, nil
	} else if result.Err() != nil {
		return nil, result.Err()
	}
	var ipPool models.IpPoolModel
	if err := result.Decode(&ipPool); err != nil {
		return nil, err
	}
	return &ipPool, nil
}

func (r *IpPoolRepositoryImpl) SavePool(ipPool *models.IpPoolModel) (*models.IpPoolModel, error) {
	result, err := r.ipPoolCollection.InsertOne(context.TODO(), ipPool)
	if err != nil {
		return nil, err
	}
	ipPool.Id = result.InsertedID.(primitive.ObjectID)
	return ipPool, nil
}

func (r *IpPoolRepositoryImpl) UpdatePool(ipPool *models.IpPoolModel) (*models.IpPoolModel, error) {
	update := bson.M{
		"$set": ipPool,
	}
	result, err := r.ipPoolCollection.UpdateByID(context.TODO(), ipPool.Id, update)
	if err != nil {
		return nil, err
	}
	if result.ModifiedCount != 1 {
		return nil, fmt.Errorf("update of IpPoolModel %s failed cause update count is %d", ipPool.Id.Hex(), result.ModifiedCount)
	}

	return ipPool, nil
}
