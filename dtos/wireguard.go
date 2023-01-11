package dtos

import (
	"net"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"
)

type WireguardPeerDto struct {
	Id              string          `json:"id,omitempty"`
	Username        string          `json:"username,omitempty"`
	PrivateKey      *string         `json:"private-key,omitempty"`
	PublicKey       *string         `json:"public-key,omitempty"`
	PeerIp          net.IP          `json:"peer-ip,omitempty"`
	PreSharedKey    *string         `json:"psk,omitempty"`
	Description     *string         `json:"description,omitempty"`
	State           string          `json:"state,omitempty" bson:"state,omitempty"`
	ProvisionStatus *string         `json:"provision-status,omitempty"`
	Endpoint        string          `json:"endpoint,omitempty"`
	RemotePubKey    string          `json:"remote-pub-key,omitempty"`
	Networks        []utils.IPnMask `json:"networks,omitempty"` // net.IPNet cannot be json serialized
}

func ToWireguardPeerDto(model *models.WireGuardAggregatedPeerModel) *WireguardPeerDto {
	nets := make([]utils.IPnMask, 0)
	for _, ipMask := range model.Networks {
		nets = append(nets, utils.NewIPnMaskFromNet(ipMask))
	}

	return &WireguardPeerDto{
		Id:              model.Id.Hex(),
		Username:        model.Username,
		State:           model.State.String(),
		PeerIp:          model.Ip,
		Networks:        nets,
		RemotePubKey:    model.RemotePubKey,
		Endpoint:        model.Endpoint,
		PrivateKey:      utils.StringToNilPointer(model.PrivateKey),
		PublicKey:       utils.StringToNilPointer(model.PublicKey),
		PreSharedKey:    utils.StringToNilPointer(model.PreSharedKey),
		Description:     utils.StringToNilPointer(model.Description),
		ProvisionStatus: utils.StringToNilPointer(model.ProvisionStatus),
	}
}

type WireguardTunnelProfileDto struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type WireguardTunnelDto struct {
	Id       string                      `json:"id,omitempty"`
	Name     string                      `json:"name,omitempty"`
	Profiles []WireguardTunnelProfileDto `json:"profiles,omitempty"`
}

func ToWireguardTunnelProfileDto(profileInfo *models.WireguardTunnelProfileInfo) *WireguardTunnelProfileDto {
	return &WireguardTunnelProfileDto{Id: profileInfo.Id, Name: profileInfo.Name}
}

func ToWireguardTunnelDto(tunnelInfo *models.WireguardTunnelInfo) *WireguardTunnelDto {
	profiles := make([]WireguardTunnelProfileDto, 0)
	for _, prof := range tunnelInfo.Profiles {
		profiles = append(profiles, WireguardTunnelProfileDto{Name: prof.Name, Id: prof.Id})
	}
	return &WireguardTunnelDto{Id: tunnelInfo.Id, Name: tunnelInfo.Name, Profiles: profiles}
}

type WireguardPeerRequestDto struct {
	Description  *string `json:"description,omitempty"`
	PreSharedKey *string `json:"psk,omitempty"`
}
