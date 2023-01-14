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
	ProvisionStateUnprovisioning
	ProvisionStateUnprovisioned
	ProvisionStateDeleting
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
	case ProvisionStateUnprovisioned:
		return "UNPROVISIONED"
	case ProvisionStateUnprovisioning:
		return "UNPROVISIONING"
	case ProvisionStateDeleting:
		return "DELETING"
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
	InterfaceName   string             `json:"interface-name,omitempty" bson:"interface-name"`
	Ip              net.IP             `json:"ip,omitempty" bson:"ip"`
}

func (w WireguardPeerModel) String() string {

	return fmt.Sprintf("WireguardPeerModel[Id=%v, Username=%s, PrivateKey=%s, PublicKey=%s, "+
		"PreSharedKey=<not-diplayed>, Description=%v, State=%s, ProvisionStatus=%v, CreationTime=%v, "+
		"ProfileId=%s, TunnelId=%s, InterfaceName=%s]", w.Id, w.Username,
		utils.MasqueradeSensitiveString(w.PrivateKey, 5),
		utils.MasqueradeSensitiveString(w.PublicKey, 5), w.Description, w.State, w.ProvisionStatus,
		w.CreationTime, w.ProfileId, w.TunnelId, w.InterfaceName)
}

type WireGuardAggregatedPeerModel struct {
	WireguardPeerModel
	Networks     []net.IPNet
	Endpoint     string
	RemotePubKey string
}

type IpPoolModel struct {
	Id       primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Provider string             `json:"provider,omitempty" bson:"provider"`
	Tunnel   string             `json:"tunnel,omitempty" bson:"tunnel"`
	InUse    []net.IP           `json:"in-use,omitempty" bson:"in-use"`
	Reserved []net.IP           `json:"reserved,omitempty" bson:"reserved"`
	Network  net.IPNet          `json:"network,omitempty" bson:"network"`
}

func (w IpPoolModel) String() string {
	return fmt.Sprintf("IpPoolModel[Id=%v, Provider=%s, Tunnel=%s, InUse=%v, Reserved=%v, Network=%v]",
		w.Id, w.Provider, w.Tunnel, w.InUse, w.Reserved, w.Network)
}

type WireguardInterfaceModel struct {
	Id        primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Provider  string             `json:"provider,omitempty" bson:"provider"`
	Name      string             `json:"name,omitempty" bson:"name"`
	Endpoint  string             `json:"endpoint,omitempty" bson:"dns"`
	PublicKey string             `json:"public-key,omitempty" bson:"public-key"`
}

func (w WireguardInterfaceModel) String() string {
	return fmt.Sprintf("WireguardInterfaceModel[Id=%v, Name=%s, Provider=%s, Endpoint=%s, PublicKey=%s]",
		w.Id, w.Name, w.Provider, w.Endpoint, utils.MasqueradeSensitiveString(w.PublicKey, 5))
}

type WireguardTunnelProfileInfo struct {
	Id     string
	Name   string
	Ranges []net.IPNet
}

func (w WireguardTunnelProfileInfo) String() string {
	return fmt.Sprintf("WireguardTunnelProfileInfo[Id=%s, Name=%s, Ranges=%v]", w.Id,
		w.Name, w.Ranges)
}

type WireguardTunnelInfo struct {
	Id        string
	Name      string
	Provider  string
	Interface string
	Profiles  map[string]WireguardTunnelProfileInfo
}

func (w WireguardTunnelInfo) String() string {
	return fmt.Sprintf("WireguardTunnelInfo[Id=%s, Name=%s, Provider=%s, Interface=%s, Profiles=%v]", w.Id,
		w.Name, w.Provider, w.Interface, w.Profiles)
}
