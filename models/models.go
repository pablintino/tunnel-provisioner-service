package models

import (
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

const (
	ProvisionStateProvisioning = iota
	ProvisionStateProvisioned
	ProvisionStateError
)

type ProvisioningState int

func (e ProvisioningState) String() string {
	switch e {
	case ProvisionStateProvisioning:
		return "PROVISIONED"
	case ProvisionStateProvisioned:
		return "PROVISIONED"
	case ProvisionStateError:
		return "ERROR"
	default:
		return fmt.Sprintf("%d", int(e))
	}
}

const (
	ProviderTypeRouterOS = iota
)

type ProviderType int

type WireguardPeerModel struct {
	Id              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Username        string             `json:"username,omitempty" bson:"username,omitempty"`
	PrivateKey      string             `json:"private-key,omitempty" bson:"private-key,omitempty"`
	PublicKey       string             `json:"public-key,omitempty" bson:"public-key,omitempty"`
	PreSharedKey    *string            `json:"psk,omitempty" bson:"psk,omitempty"`
	Description     *string            `json:"description,omitempty" bson:"description,omitempty"`
	State           ProvisioningState  `json:"state,omitempty" bson:"state,omitempty"`
	ProvisionStatus *string            `json:"provision-status,omitempty" bson:"provision-status,omitempty"`
	CreationTime    time.Time          `json:"creation-time,omitempty" bson:"creation-time,omitempty"`
}

type WireguardProfile struct {
	Id     primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name   string             `json:"name,omitempty" bson:"name,omitempty"`
	Ranges []string           `json:"ranges,omitempty" bson:"ranges,omitempty"`
}

type WireguardTunnelProfileInfo struct {
	Id     string
	Name   string
	Ranges []net.IPNet
}

type WireguardTunnelInfo struct {
	Id       string
	Name     string
	Provider ProviderType
	Profiles map[string]WireguardTunnelProfileInfo
}
