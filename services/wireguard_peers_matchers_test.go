package services_test

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"reflect"
	"testing"
	"time"
	"tunnel-provisioner-service/models"
)

type PeerMatcher interface {
	Evaluate(model *models.WireguardPeerModel) bool
}

type PeerIdMatcher struct {
	id primitive.ObjectID
}

func NewPeerIdMatcherFromModel(model *models.WireguardPeerModel) *PeerIdMatcher {
	return &PeerIdMatcher{id: model.Id}
}

func (m *PeerIdMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.id.String() == model.Id.String()
}

type PeerIpMatcher struct {
	ip net.IP
}

func NewPeerIpMatcherFromModel(model *models.WireguardPeerModel) *PeerIpMatcher {
	return &PeerIpMatcher{ip: model.Ip}
}

func NewPeerIpMatcher(ip net.IP) *PeerIpMatcher {
	return &PeerIpMatcher{ip: ip}
}

func (m *PeerIpMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.ip.Equal(model.Ip)
}

type PeerStateMatcher struct {
	state models.ProvisioningState
}

func NewPeerStateMatcherFromModel(model *models.WireguardPeerModel) *PeerStateMatcher {
	return &PeerStateMatcher{state: model.State}
}

func (m *PeerStateMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.state == model.State
}

type PeerStatusMatcher struct {
	status string
}

func NewPeerStatusMatcherFromModel(model *models.WireguardPeerModel) *PeerStatusMatcher {
	return &PeerStatusMatcher{status: model.ProvisionStatus}
}

func (m *PeerStatusMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.status == model.ProvisionStatus
}

type PeerPublicKeyMatcher struct {
	publicKey string
}

func NewPeerPublicKeyMatcherFromModel(model *models.WireguardPeerModel) *PeerPublicKeyMatcher {
	return &PeerPublicKeyMatcher{publicKey: model.PublicKey}
}

func NewPeerPublicKeyMatcher(publicKey string) *PeerPublicKeyMatcher {
	return &PeerPublicKeyMatcher{publicKey: publicKey}
}

func (m *PeerPublicKeyMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	if m.publicKey != "" {
		if _, err := wgtypes.ParseKey(model.PublicKey); err != nil {
			return false
		}
	}

	return m.publicKey == model.PublicKey
}

type PeerPrivateKeyMatcher struct {
	privateKey string
}

func NewPeerPrivateKeyMatcherFromModel(model *models.WireguardPeerModel) *PeerPrivateKeyMatcher {
	return &PeerPrivateKeyMatcher{privateKey: model.PrivateKey}
}

func NewPeerPrivateKeyMatcher(privateKey string) *PeerPrivateKeyMatcher {
	return &PeerPrivateKeyMatcher{privateKey: privateKey}
}

func (m *PeerPrivateKeyMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	if m.privateKey != "" {
		if _, err := wgtypes.ParseKey(model.PrivateKey); err != nil {
			return false
		}
	}

	return m.privateKey == model.PrivateKey
}

type PeerPSKMatcher struct {
	psk string
}

func NewPeerPSKMatcherFromModel(model *models.WireguardPeerModel) *PeerPSKMatcher {
	return &PeerPSKMatcher{psk: model.PreSharedKey}
}

func (m *PeerPSKMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	if m.psk != "" {
		if _, err := wgtypes.ParseKey(model.PreSharedKey); err != nil {
			return false
		}
	}

	return m.psk == model.PreSharedKey
}

type PeerProfileIdMatcher struct {
	profileId string
}

func NewPeerProfileIdMatcherFromModel(model *models.WireguardPeerModel) *PeerProfileIdMatcher {
	return &PeerProfileIdMatcher{profileId: model.ProfileId}
}

func (m *PeerProfileIdMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.profileId == model.ProfileId
}

type PeerTunnelIdMatcher struct {
	tunnelId string
}

func NewPeerTunnelIdMatcherFromModel(model *models.WireguardPeerModel) *PeerTunnelIdMatcher {
	return &PeerTunnelIdMatcher{tunnelId: model.TunnelId}
}

func (m *PeerTunnelIdMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.tunnelId == model.TunnelId
}

type PeerUsernameMatcher struct {
	username string
}

func NewPeerUsernameMatcherFromModel(model *models.WireguardPeerModel) *PeerUsernameMatcher {
	return &PeerUsernameMatcher{username: model.Username}
}

func (m *PeerUsernameMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.username == model.Username
}

type PeerDescriptionMatcher struct {
	description string
}

func NewPeerDescriptionMatcherFromModel(model *models.WireguardPeerModel) *PeerDescriptionMatcher {
	return &PeerDescriptionMatcher{description: model.Description}
}

func (m *PeerDescriptionMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.description == model.Description
}

type PeerCreationTimeMatcher struct {
	creationTime time.Time
}

func NewPeerCreationTimeMatcherFromModel(model *models.WireguardPeerModel) *PeerCreationTimeMatcher {
	return &PeerCreationTimeMatcher{creationTime: model.CreationTime}
}

func (m *PeerCreationTimeMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	return m.creationTime.Equal(model.CreationTime)
}

type PkPubKeysMatcher struct {
	expectedPubKey string
}

func NewPkPubKeysMatcher() *PkPubKeysMatcher {
	return &PkPubKeysMatcher{}
}

func (m *PkPubKeysMatcher) SetPublicKey(pubKey string) {
	m.expectedPubKey = pubKey
}

func (m *PkPubKeysMatcher) Evaluate(model *models.WireguardPeerModel) bool {
	// Value externally set. If nil not ready
	if m.expectedPubKey == "" || m.expectedPubKey != model.PublicKey {
		return false
	}

	privateKey, err := wgtypes.ParseKey(model.PrivateKey)
	if err != nil {
		return false
	}
	publicKey, err := wgtypes.ParseKey(model.PublicKey)
	if err != nil {
		return false
	}
	privateBytes := [32]byte(privateKey)
	publicBytes := [32]byte(publicKey)
	// Verify that the public key comes from the pk
	if _, err := curve25519.X25519(privateBytes[:], publicBytes[:]); err == nil {
		return true
	}
	return false
}

type ListPeerMatcher struct {
	t        *testing.T
	matchers []PeerMatcher
}

func NewListPeerMatcher(t *testing.T) *ListPeerMatcher {
	return &ListPeerMatcher{t: t}
}

func (e *ListPeerMatcher) Add(matchers ...PeerMatcher) *ListPeerMatcher {
	e.matchers = append(e.matchers, matchers...)
	return e
}

func (e *ListPeerMatcher) Matches(x interface{}) bool {
	// Check if types assignable and convert them to common type
	xVal, ok := reflect.ValueOf(x).Interface().(*models.WireguardPeerModel)
	if !ok {
		e.t.Fatal("Cannot cast mock arguments to a WireguardPeerModel")
		return false
	}

	for _, matcher := range e.matchers {
		if res := matcher.Evaluate(xVal); !res {
			return res
		}
	}

	return true
}

func (e *ListPeerMatcher) String() string {
	return "list peer matcher"
}

func NewAllMatchersPeerMatcher(t *testing.T, model *models.WireguardPeerModel) *ListPeerMatcher {
	return &ListPeerMatcher{
		t: t,
		matchers: []PeerMatcher{
			NewPeerIdMatcherFromModel(model),
			NewPeerCreationTimeMatcherFromModel(model),
			NewPeerIpMatcherFromModel(model),
			NewPeerStateMatcherFromModel(model),
			NewPeerStatusMatcherFromModel(model),
			NewPeerPublicKeyMatcherFromModel(model),
			NewPeerPrivateKeyMatcherFromModel(model),
			NewPeerPSKMatcherFromModel(model),
			NewPeerTunnelIdMatcherFromModel(model),
			NewPeerProfileIdMatcherFromModel(model),
			NewPeerUsernameMatcherFromModel(model),
			NewPeerDescriptionMatcherFromModel(model),
		},
	}
}

func NewIgnoreIdAndCreationTimePeerMatcher(t *testing.T, model *models.WireguardPeerModel) *ListPeerMatcher {
	return &ListPeerMatcher{
		t: t,
		matchers: []PeerMatcher{
			NewPeerIpMatcherFromModel(model),
			NewPeerStateMatcherFromModel(model),
			NewPeerStatusMatcherFromModel(model),
			NewPeerPublicKeyMatcherFromModel(model),
			NewPeerPrivateKeyMatcherFromModel(model),
			NewPeerPSKMatcherFromModel(model),
			NewPeerTunnelIdMatcherFromModel(model),
			NewPeerProfileIdMatcherFromModel(model),
			NewPeerUsernameMatcherFromModel(model),
			NewPeerDescriptionMatcherFromModel(model),
		},
	}
}

func NewIgnoreKeysPeerMatcher(t *testing.T, model *models.WireguardPeerModel) *ListPeerMatcher {
	return &ListPeerMatcher{
		t: t,
		matchers: []PeerMatcher{
			NewPeerIpMatcherFromModel(model),
			NewPeerIdMatcherFromModel(model),
			NewPeerCreationTimeMatcherFromModel(model),
			NewPeerStateMatcherFromModel(model),
			NewPeerStatusMatcherFromModel(model),
			NewPeerPSKMatcherFromModel(model),
			NewPeerTunnelIdMatcherFromModel(model),
			NewPeerProfileIdMatcherFromModel(model),
			NewPeerUsernameMatcherFromModel(model),
			NewPeerDescriptionMatcherFromModel(model),
		},
	}
}
