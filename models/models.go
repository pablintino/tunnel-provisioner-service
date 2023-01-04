package models

import (
	"fmt"
	"net"
	"time"
	"tunnel-provisioner-service/utils"

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
		return "PROVISIONING"
	case ProvisionStateProvisioned:
		return "PROVISIONED"
	case ProvisionStateError:
		return "ERROR"
	default:
		return fmt.Sprintf("%d", int(e))
	}
}

type WireguardPeerModel struct {
	Id              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Username        string             `json:"username,omitempty" bson:"username"`
	PrivateKey      string             `json:"private-key,omitempty" bson:"private-key"`
	PublicKey       string             `json:"public-key,omitempty" bson:"public-key"`
	PreSharedKey    string             `json:"psk,omitempty" bson:"psk"`
	Description     string             `json:"description,omitempty" bson:"description"`
	State           ProvisioningState  `json:"state,omitempty" bson:"state"`
	ProvisionStatus string             `json:"provision-status,omitempty" bson:"provision-status"`
	CreationTime    time.Time          `json:"creation-time,omitempty" bson:"creation-time"`
	ProfileId       string             `json:"profile-id,omitempty" bson:"profile-id"`
	TunnelId        string             `json:"tunnel-id,omitempty" bson:"tunnel-id"`
}

func (w WireguardPeerModel) String() string {

	return fmt.Sprintf("WireguardPeerModel[Id=%s, Username=%s, PrivateKey=%s, PublicKey=%s, "+
		"PreSharedKey=<not-diplayed>, Description=%v, State=%s, ProvisionStatus=%v, CreationTime=%v, "+
		"ProfileId=%s, TunnelId=%s]", w.Id, w.Username, utils.MasqueradeSensitiveString(w.PrivateKey, 5),
		utils.MasqueradeSensitiveString(w.PublicKey, 5), w.Description, w.State, w.ProvisionStatus,
		w.CreationTime, w.ProfileId, w.TunnelId)
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
	Id        string
	Name      string
	Provider  string
	Interface string
	Profiles  map[string]WireguardTunnelProfileInfo
}
