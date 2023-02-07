package services_test

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/services"
	"tunnel-provisioner-service/utils"
)

type WaitingMockWireguardPeersRepository struct {
	mock                 *MockWireguardPeersRepository
	WgGetPeersByUsername sync.WaitGroup
	WgGetPeersByTunnelId sync.WaitGroup
	WgGetPeerById        sync.WaitGroup
	WgSavePeer           sync.WaitGroup
	WgUpdatePeer         sync.WaitGroup
	WgDeletePeer         sync.WaitGroup
	WgGetAll             sync.WaitGroup
}

func NewWaitingMockWireguardPeersRepository(ctrl *gomock.Controller) *WaitingMockWireguardPeersRepository {
	return &WaitingMockWireguardPeersRepository{mock: NewMockWireguardPeersRepository(ctrl)}
}

func (m *WaitingMockWireguardPeersRepository) EXPECT() *MockWireguardPeersRepositoryMockRecorder {
	return m.mock.EXPECT()
}

func (m *WaitingMockWireguardPeersRepository) GetPeersByUsername(username string) ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeersByUsername(username)
	m.WgGetPeersByUsername.Done()
	return val, err
}
func (m *WaitingMockWireguardPeersRepository) GetPeersByTunnelId(tunnelId string) ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeersByTunnelId(tunnelId)
	m.WgGetPeersByTunnelId.Done()
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) GetPeerById(username, id string) (*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeerById(username, id)
	m.WgGetPeerById.Done()
	return val, err
}
func (m *WaitingMockWireguardPeersRepository) SavePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	val, err := m.mock.SavePeer(peer)
	m.WgSavePeer.Done()
	return val, err
}
func (m *WaitingMockWireguardPeersRepository) UpdatePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	val, err := m.mock.UpdatePeer(peer)
	m.WgUpdatePeer.Done()
	return val, err
}
func (m *WaitingMockWireguardPeersRepository) GetAll() ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetAll()
	m.WgGetAll.Done()
	return val, err
}
func (m *WaitingMockWireguardPeersRepository) DeletePeer(peer *models.WireguardPeerModel) error {
	err := m.mock.DeletePeer(peer)
	m.WgDeletePeer.Done()
	return err
}

type AnyWgKeyMatcher struct {
}

func NewAnyWgKeyMatcher() *AnyWgKeyMatcher {
	return &AnyWgKeyMatcher{}

}

func (e AnyWgKeyMatcher) Matches(x interface{}) bool {
	v := reflect.ValueOf(x)
	if v.Kind() == reflect.String {
		if _, err := wgtypes.ParseKey(v.String()); err == nil {
			return true
		}
	}

	return false
}

func (e AnyWgKeyMatcher) String() string {
	return "is a wg key "
}

type PeerMatcher struct {
	x                  *models.WireguardPeerModel
	t                  *testing.T
	ignorePublickey    bool
	ignorePrivatekey   bool
	ignoreCreationTime bool
	ignoreId           bool
}

func NewPeerMatcher(x *models.WireguardPeerModel, t *testing.T, ignorePublickey, ignorePrivatekey, ignoreCreationTime, ignoreId bool) PeerMatcher {
	return PeerMatcher{x: x, t: t, ignorePublickey: ignorePublickey, ignorePrivatekey: ignorePrivatekey, ignoreCreationTime: ignoreCreationTime, ignoreId: ignoreId}
}

func (e PeerMatcher) Matches(x interface{}) bool {
	// In case, some value is nil
	if e.x == nil || x == nil {
		return reflect.DeepEqual(e.x, x)
	}

	// Check if types assignable and convert them to common type
	xVal, ok := reflect.ValueOf(x).Interface().(*models.WireguardPeerModel)
	if !ok {
		e.t.Fatal("Cannot cast mock arguments to a WireguardPeerModel")
		return false
	}

	if xVal.PreSharedKey != e.x.PreSharedKey ||
		xVal.Description != e.x.Description ||
		xVal.Username != e.x.Username ||
		xVal.TunnelId != e.x.TunnelId ||
		xVal.ProfileId != e.x.ProfileId ||
		xVal.ProvisionStatus != e.x.ProvisionStatus ||
		xVal.State != e.x.State ||
		!e.x.Ip.Equal(xVal.Ip) ||
		(!e.ignoreId && (xVal.Id.Hex() != e.x.Id.Hex())) ||
		(!e.ignoreCreationTime && (!xVal.CreationTime.Equal(e.x.CreationTime))) ||
		(!e.ignorePublickey && (xVal.PublicKey != e.x.PublicKey)) ||
		(!e.ignorePrivatekey && (xVal.PrivateKey != e.x.PrivateKey)) {
		return false
	}

	return true
}

func (e PeerMatcher) String() string {
	return fmt.Sprintf("is equal to %v (%T)", e.x, e.x)
}

func waitWatchGroup(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true // completed normally
	case <-time.After(timeout):
		return false // timed out
	}
}

func TestWireguardPeersServiceImplCreatePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	ctrl := gomock.NewController(t)

	wireguardPeersRepositoryMock := NewWaitingMockWireguardPeersRepository(ctrl)
	usersServiceMock := NewMockUsersService(ctrl)
	tunnelsServiceMock := NewMockWireguardTunnelService(ctrl)
	wireguardProviderMock := NewMockWireguardTunnelProvider(ctrl)
	poolServiceMock := NewMockPoolService(ctrl)

	const providerName = "routeros"
	providerMap := map[string]services.WireguardTunnelProvider{
		providerName: wireguardProviderMock,
	}

	peersService := services.NewWireguardPeersService(
		wireguardPeersRepositoryMock,
		providerMap,
		poolServiceMock,
		tunnelsServiceMock,
		usersServiceMock,
	)

	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	profileInfo := models.WireguardTunnelProfileInfo{
		Name:   "test-profile",
		Id:     utils.GenerateInternalIdFromString("test-profile"),
		Ranges: []net.IPNet{*net1, *net2, *net3},
	}
	tunnelInfo := models.WireguardTunnelInfo{
		Name:      "test-tunnel",
		Id:        utils.GenerateInternalIdFromString("test-tunnel"),
		Provider:  providerName,
		Interface: models.WireguardInterfaceModel{Name: "test-interface", Present: true, Provider: providerName},
	}

	tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(tunnelInfo.Id), gomock.Eq(profileInfo.Id)).
		Return(tunnelInfo, profileInfo, nil).
		AnyTimes()

	mockedSavedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "test-username",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		State:        models.ProvisionStateCreated,
		ProfileId:    profileInfo.Id,
		TunnelId:     tunnelInfo.Id,
		Ip:           net.IPv4zero,
		CreationTime: time.Now(),
	}
	wireguardPeersRepositoryMock.EXPECT().
		SavePeer(NewPeerMatcher(mockedSavedPeer, t, false, false, true, true)).
		Return(mockedSavedPeer, nil)

	peerIp := net.IPv4(192, 168, 177, 2)
	poolServiceMock.EXPECT().GetNextIp(gomock.Eq(&tunnelInfo)).Return(peerIp, nil)

	/* REPOSITORY: Prepare first update after acquiring an IP */
	updatePeerResponseIpSave := &models.WireguardPeerModel{
		Id:           mockedSavedPeer.Id,
		Username:     mockedSavedPeer.Username,
		Description:  mockedSavedPeer.Description,
		PreSharedKey: mockedSavedPeer.PreSharedKey,
		State:        mockedSavedPeer.State,
		ProfileId:    mockedSavedPeer.ProfileId,
		TunnelId:     mockedSavedPeer.TunnelId,
		Ip:           peerIp,
		CreationTime: mockedSavedPeer.CreationTime,
	}
	wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(updatePeerResponseIpSave, t, false, false, false, false)).
		Return(updatePeerResponseIpSave, nil)

	/* REPOSITORY: Prepare intermediate update as PROVISIONING */
	updatePeerResponseProvisioningSave := &models.WireguardPeerModel{
		Id:           updatePeerResponseIpSave.Id,
		Username:     updatePeerResponseIpSave.Username,
		Description:  updatePeerResponseIpSave.Description,
		PreSharedKey: updatePeerResponseIpSave.PreSharedKey,
		State:        models.ProvisionStateProvisioning,
		ProfileId:    updatePeerResponseIpSave.ProfileId,
		TunnelId:     updatePeerResponseIpSave.TunnelId,
		Ip:           updatePeerResponseIpSave.Ip,
		CreationTime: mockedSavedPeer.CreationTime,
	}
	wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(updatePeerResponseProvisioningSave, t, false, false, false, false)).
		Return(updatePeerResponseProvisioningSave, nil)

	/* REPOSITORY: Prepare last Update for final save as PROVISIONED */
	updatePeerResponseProvisionedSave := &models.WireguardPeerModel{
		Id:           updatePeerResponseIpSave.Id,
		Username:     updatePeerResponseIpSave.Username,
		Description:  updatePeerResponseIpSave.Description,
		PreSharedKey: updatePeerResponseIpSave.PreSharedKey,
		State:        models.ProvisionStateProvisioned,
		ProfileId:    updatePeerResponseIpSave.ProfileId,
		TunnelId:     updatePeerResponseIpSave.TunnelId,
		Ip:           updatePeerResponseIpSave.Ip,
		CreationTime: mockedSavedPeer.CreationTime,
	}
	wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(updatePeerResponseProvisionedSave, t, true, true, false, false)).
		Return(updatePeerResponseProvisionedSave, nil)

	/* PROVIDER: Prepare for CreatePeer call to provider */
	providerPeer := &services.WireguardProviderPeer{}
	wireguardProviderMock.EXPECT().
		CreatePeer(
			NewAnyWgKeyMatcher(),
			gomock.Eq(updatePeerResponseProvisioningSave.Description),
			gomock.Eq(updatePeerResponseProvisioningSave.PreSharedKey),
			gomock.Eq(&tunnelInfo),
			gomock.Eq(&profileInfo),
			gomock.Eq(peerIp)).Return(providerPeer, nil)

	// Wait till state goes to provisioned
	wireguardPeersRepositoryMock.WgUpdatePeer.Add(3)
	wireguardPeersRepositoryMock.WgSavePeer.Add(1)

	// Call method under test
	result, err := peersService.CreatePeer(
		mockedSavedPeer.Username,
		tunnelInfo.Id,
		profileInfo.Id,
		mockedSavedPeer.Description,
		mockedSavedPeer.PreSharedKey,
	)

	assert.NotNil(t, result)
	assert.Nil(t, err)

	// Wait till las update is done
	assert.True(t, waitWatchGroup(&wireguardPeersRepositoryMock.WgUpdatePeer, time.Second*2))
}
