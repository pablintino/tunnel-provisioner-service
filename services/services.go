package services

import (
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ErrServiceNotFoundEntity = errors.New("service entity not found")

type BooteableService interface {
	OnBoot() error
}

type DisposableService interface {
	OnClose()
}

func buildWireguardApiPair() (*WireguardPeerKeyPair, error) {
	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	return &WireguardPeerKeyPair{
		PublicKey:  peerPrivateKey.PublicKey().String(),
		PrivateKey: peerPrivateKey.String(),
	}, nil
}

func checkWireguardPreSharedKeyIsValid(key string) bool {
	if len(key) == 0 {
		return true
	}

	_, err := wgtypes.ParseKey(key)
	return err == nil
}
