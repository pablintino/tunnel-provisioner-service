package dtos

import "tunnel-provisioner-service/models"

type WireguardPeerDto struct {
	Id              string  `json:"id,omitempty"`
	Username        string  `json:"username,omitempty"`
	PrivateKey      *string `json:"private-key,omitempty"`
	PublicKey       *string `json:"public-key,omitempty"`
	PreSharedKey    *string `json:"psk,omitempty"`
	Description     *string `json:"description,omitempty"`
	State           string  `json:"state,omitempty" bson:"state,omitempty"`
	ProvisionStatus *string `json:"provision-status,omitempty"`
}

func ToWireguardPeerDto(model *models.WireguardPeerModel) *WireguardPeerDto {
	return &WireguardPeerDto{
		Id:              model.Id.Hex(),
		Username:        model.Username,
		PrivateKey:      model.PrivateKey,
		PublicKey:       model.PublicKey,
		PreSharedKey:    model.PreSharedKey,
		Description:     model.Description,
		State:           model.State.String(),
		ProvisionStatus: model.ProvisionStatus,
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
