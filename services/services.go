package services

import (
	"encoding/base64"
	"errors"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ErrServiceNotFoundEntity = errors.New("service entity not found")

type BooteableService interface {
	OnBoot() error
}

type DisposableService interface {
	OnClose() error
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

	rawDecodedText, err := base64.StdEncoding.DecodeString(key)
	return err != nil || len(rawDecodedText) == wgtypes.KeyLen
}
