package services_test

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"reflect"
	"testing"
	"time"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/services"
	"tunnel-provisioner-service/utils"
)

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

type peersFsmMockedEntities struct {
	wireguardPeersRepositoryMock *WaitingMockWireguardPeersRepository
	usersServiceMock             *MockUsersService
	tunnelsServiceMock           *MockWireguardTunnelService
	wireguardProviderMock        *MockWireguardTunnelProvider
	poolServiceMock              *WaitingMockPoolService
	peersService                 *services.WireguardPeersServiceImpl
	tunnelInfo                   models.WireguardTunnelInfo
	profileInfo                  models.WireguardTunnelProfileInfo
	userList                     []models.User
	userMap                      map[string]models.User
}

func newPeersFsmMockedEntities(t *testing.T) *peersFsmMockedEntities {
	ctrl := gomock.NewController(t)
	entities := &peersFsmMockedEntities{}
	entities.wireguardPeersRepositoryMock = NewWaitingMockWireguardPeersRepository(ctrl, t)
	entities.usersServiceMock = NewMockUsersService(ctrl)
	entities.tunnelsServiceMock = NewMockWireguardTunnelService(ctrl)
	entities.wireguardProviderMock = NewMockWireguardTunnelProvider(ctrl)
	entities.poolServiceMock = NewWaitingMockPoolService(ctrl, t)

	const providerName = "routeros"
	providerMap := map[string]services.WireguardTunnelProvider{
		providerName: entities.wireguardProviderMock,
	}

	entities.userMap = map[string]models.User{
		"test-user-1": {Username: "test-user-1", Email: "testuser1@test.com"},
		"test-user-2": {Username: "test-user-2", Email: "testuser2@test.com"},
	}

	for _, u := range entities.userMap {
		entities.userList = append(entities.userList, u)
	}

	entities.peersService = services.NewWireguardPeersService(
		entities.wireguardPeersRepositoryMock,
		providerMap,
		entities.poolServiceMock,
		entities.tunnelsServiceMock,
		entities.usersServiceMock,
	)

	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	entities.profileInfo = models.WireguardTunnelProfileInfo{
		Name:   "test-profile",
		Id:     utils.GenerateInternalIdFromString("test-profile"),
		Ranges: []net.IPNet{*net1, *net2, *net3},
	}
	entities.tunnelInfo = models.WireguardTunnelInfo{
		Name:      "test-tunnel",
		Id:        utils.GenerateInternalIdFromString("test-tunnel"),
		Provider:  providerName,
		Interface: models.WireguardInterfaceModel{Name: "test-interface", Present: true, Provider: providerName},
	}
	return entities
}

func TestWireguardPeersServiceImplCreatePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	mockedSavedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "test-username",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		State:        models.ProvisionStateCreated,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4zero,
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		SavePeer(NewPeerMatcher(mockedSavedPeer, t, false, false, true, true)).
		Return(mockedSavedPeer, nil)

	peerIp := net.IPv4(192, 168, 177, 2)
	entities.poolServiceMock.EXPECT().GetNextIp(gomock.Eq(&entities.tunnelInfo)).Return(peerIp, nil)

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
	entities.wireguardPeersRepositoryMock.EXPECT().
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
	entities.wireguardPeersRepositoryMock.EXPECT().
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
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(updatePeerResponseProvisionedSave, t, true, true, false, false)).
		Return(updatePeerResponseProvisionedSave, nil)

	/* PROVIDER: Prepare for CreatePeer call to provider */
	providerPeer := &services.WireguardProviderPeer{}
	entities.wireguardProviderMock.EXPECT().
		CreatePeer(
			NewAnyWgKeyMatcher(),
			gomock.Eq(updatePeerResponseProvisioningSave.Description),
			gomock.Eq(updatePeerResponseProvisioningSave.PreSharedKey),
			gomock.Eq(&entities.tunnelInfo),
			gomock.Eq(&entities.profileInfo),
			gomock.Eq(peerIp)).Return(providerPeer, nil)

	// Wait till state goes to provisioned
	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(3)
	entities.wireguardPeersRepositoryMock.SetSavePeerExpected(1)
	entities.poolServiceMock.SetGetNextIpExpected(1)

	// Call method under test
	result, err := entities.peersService.CreatePeer(
		mockedSavedPeer.Username,
		entities.tunnelInfo.Id,
		entities.profileInfo.Id,
		mockedSavedPeer.Description,
		mockedSavedPeer.PreSharedKey,
	)

	assert.NotNil(t, result)
	assert.Nil(t, err)

	// Wait till las update is done
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplDeleteProvisionedPeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelInfo(gomock.Eq(entities.tunnelInfo.Id)).
		Return(entities.tunnelInfo, nil).
		AnyTimes()

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "test-username",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		GetPeerById(gomock.Eq(initialProvisonedPeer.Username), gomock.Eq(initialProvisonedPeer.Id.Hex())).
		Return(initialProvisonedPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&entities.tunnelInfo), gomock.Eq(initialProvisonedPeer.PublicKey)).Return(nil)

	/* REPOSITORY: Prepare last first update to go to DELETING */
	updatePeerResponseDeletingSave := &models.WireguardPeerModel{
		Id:           initialProvisonedPeer.Id,
		Username:     initialProvisonedPeer.Username,
		Description:  initialProvisonedPeer.Description,
		PreSharedKey: initialProvisonedPeer.PreSharedKey,
		PublicKey:    initialProvisonedPeer.PublicKey,
		State:        models.ProvisionStateDeleting,
		ProfileId:    initialProvisonedPeer.ProfileId,
		TunnelId:     initialProvisonedPeer.TunnelId,
		Ip:           initialProvisonedPeer.Ip,
		CreationTime: initialProvisonedPeer.CreationTime,
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(updatePeerResponseDeletingSave, t, false, false, false, false)).
		Return(updatePeerResponseDeletingSave, nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		DeletePeer(NewPeerMatcher(updatePeerResponseDeletingSave, t, false, false, false, false)).
		Return(nil)

	entities.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&entities.tunnelInfo), gomock.Eq(initialProvisonedPeer.Ip)).Return(nil)

	// Wait till state goes to deleted
	entities.wireguardPeersRepositoryMock.SetGetPeerByIdExpected(1)
	entities.wireguardPeersRepositoryMock.SetDeletePeerExpected(1)
	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(1)
	entities.poolServiceMock.SetRemoveIpExpected(1)

	err := entities.peersService.DeletePeer(initialProvisonedPeer.Username, initialProvisonedPeer.Id.Hex())

	assert.Nil(t, err)

	// Wait till last update is done
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
	entities.poolServiceMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplSyncProvisionedPeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.usersServiceMock.EXPECT().GetUsers().Return(entities.userMap, nil)

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     entities.userList[0].Username,
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialProvisonedPeer}, nil)
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{entities.tunnelInfo.Id: entities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		MaxTimes(1)

	providerPeer := &services.WireguardProviderPeer{
		PublicKey:      initialProvisonedPeer.PublicKey,
		Disabled:       false,
		Id:             "*1D",
		Description:    initialProvisonedPeer.Description,
		AllowedAddress: entities.profileInfo.Ranges,
	}
	entities.wireguardProviderMock.EXPECT().
		GetPeerByPublicKey(gomock.Eq(initialProvisonedPeer.PublicKey), gomock.Eq(&entities.tunnelInfo)).
		Return(providerPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		UpdatePeer(
			gomock.Eq(providerPeer.Id),
			gomock.Eq(initialProvisonedPeer.PublicKey),
			gomock.Eq(initialProvisonedPeer.Description),
			gomock.Eq(initialProvisonedPeer.PreSharedKey),
			gomock.Eq(&entities.tunnelInfo),
			gomock.Eq(&entities.profileInfo),
			gomock.Eq(initialProvisonedPeer.Ip),
		).
		Return(nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(initialProvisonedPeer, t, false, false, false, false)).
		Return(initialProvisonedPeer, nil)

	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(1)
	entities.wireguardPeersRepositoryMock.SetGetAllExpected(1)

	entities.peersService.SyncPeers()

	// Wait till last update is done
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplSyncUnprovisionedPeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.usersServiceMock.EXPECT().GetUsers().Return(entities.userMap, nil)

	initialUnprovisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     entities.userList[0].Username,
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateUnprovisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialUnprovisonedPeer}, nil)
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{entities.tunnelInfo.Id: entities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	// First state update from Unprovisioned to provisioning
	provisioningPeer := &models.WireguardPeerModel{
		Id:           initialUnprovisonedPeer.Id,
		Username:     initialUnprovisonedPeer.Username,
		Description:  initialUnprovisonedPeer.Description,
		PreSharedKey: initialUnprovisonedPeer.PreSharedKey,
		PublicKey:    initialUnprovisonedPeer.PublicKey,
		State:        models.ProvisionStateProvisioning,
		ProfileId:    initialUnprovisonedPeer.ProfileId,
		TunnelId:     initialUnprovisonedPeer.TunnelId,
		Ip:           initialUnprovisonedPeer.Ip,
		CreationTime: initialUnprovisonedPeer.CreationTime,
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(provisioningPeer, t, false, false, false, false)).
		Return(provisioningPeer, nil)

	providerPeer := &services.WireguardProviderPeer{
		PublicKey:      initialUnprovisonedPeer.PublicKey,
		Disabled:       false,
		Id:             "*1D",
		Description:    initialUnprovisonedPeer.Description,
		AllowedAddress: entities.profileInfo.Ranges,
	}
	entities.wireguardProviderMock.EXPECT().
		GetPeerByPublicKey(gomock.Eq(initialUnprovisonedPeer.PublicKey), gomock.Eq(&entities.tunnelInfo)).
		Return(providerPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		UpdatePeer(
			gomock.Eq(providerPeer.Id),
			gomock.Eq(initialUnprovisonedPeer.PublicKey),
			gomock.Eq(initialUnprovisonedPeer.Description),
			gomock.Eq(initialUnprovisonedPeer.PreSharedKey),
			gomock.Eq(&entities.tunnelInfo),
			gomock.Eq(&entities.profileInfo),
			gomock.Eq(initialUnprovisonedPeer.Ip),
		).
		Return(nil)

	// Last state update from Provisioning to provisioned
	provisionedPeer := &models.WireguardPeerModel{
		Id:           provisioningPeer.Id,
		Username:     provisioningPeer.Username,
		Description:  provisioningPeer.Description,
		PreSharedKey: provisioningPeer.PreSharedKey,
		PublicKey:    provisioningPeer.PublicKey,
		State:        models.ProvisionStateProvisioned,
		ProfileId:    provisioningPeer.ProfileId,
		TunnelId:     provisioningPeer.TunnelId,
		Ip:           provisioningPeer.Ip,
		CreationTime: provisioningPeer.CreationTime,
	}

	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(provisionedPeer, t, false, false, false, false)).
		Return(provisionedPeer, nil)

	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(2)
	entities.wireguardPeersRepositoryMock.SetGetAllExpected(1)

	entities.peersService.SyncPeers()

	// Wait till last update is done
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplSyncDeletePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.usersServiceMock.EXPECT().GetUsers().Return(entities.userMap, nil)

	initialUnprovisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "non-existing-user",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialUnprovisonedPeer}, nil)
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{entities.tunnelInfo.Id: entities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	// First state update from Provisioned to deleting
	deletingPeer := &models.WireguardPeerModel{
		Id:           initialUnprovisonedPeer.Id,
		Username:     initialUnprovisonedPeer.Username,
		Description:  initialUnprovisonedPeer.Description,
		PreSharedKey: initialUnprovisonedPeer.PreSharedKey,
		PublicKey:    initialUnprovisonedPeer.PublicKey,
		State:        models.ProvisionStateDeleting,
		ProfileId:    initialUnprovisonedPeer.ProfileId,
		TunnelId:     initialUnprovisonedPeer.TunnelId,
		Ip:           initialUnprovisonedPeer.Ip,
		CreationTime: initialUnprovisonedPeer.CreationTime,
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(deletingPeer, t, false, false, false, false)).
		Return(deletingPeer, nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		DeletePeer(NewPeerMatcher(deletingPeer, t, false, false, false, false)).
		Return(nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&entities.tunnelInfo), gomock.Eq(deletingPeer.PublicKey)).
		Return(nil)

	entities.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&entities.tunnelInfo), gomock.Eq(deletingPeer.Ip)).Return(nil)

	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(1)
	entities.wireguardPeersRepositoryMock.SetDeletePeerExpected(1)
	entities.wireguardPeersRepositoryMock.SetGetAllExpected(1)
	entities.poolServiceMock.SetRemoveIpExpected(1)

	entities.peersService.SyncPeers()

	// Wait mock calls
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
	entities.poolServiceMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplSyncUnprovisionPeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.usersServiceMock.EXPECT().GetUsers().Return(entities.userMap, nil)

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     entities.userList[0].Username,
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialProvisonedPeer}, nil)

	// Key of this test. Disabled the interface
	entities.tunnelInfo.Interface.Present = false
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{entities.tunnelInfo.Id: entities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	// First state update from Provisioned to un provisioning
	unprovisioningPeer := &models.WireguardPeerModel{
		Id:           initialProvisonedPeer.Id,
		Username:     initialProvisonedPeer.Username,
		Description:  initialProvisonedPeer.Description,
		PreSharedKey: initialProvisonedPeer.PreSharedKey,
		PublicKey:    initialProvisonedPeer.PublicKey,
		State:        models.ProvisionStateUnprovisioning,
		ProfileId:    initialProvisonedPeer.ProfileId,
		TunnelId:     initialProvisonedPeer.TunnelId,
		Ip:           initialProvisonedPeer.Ip,
		CreationTime: initialProvisonedPeer.CreationTime,
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(unprovisioningPeer, t, false, false, false, false)).
		Return(unprovisioningPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&entities.tunnelInfo), gomock.Eq(unprovisioningPeer.PublicKey)).
		Return(nil)

	// Last state update from UNPROVISIONING to UNPROVISIONED
	unprovisionedPeer := &models.WireguardPeerModel{
		Id:           unprovisioningPeer.Id,
		Username:     unprovisioningPeer.Username,
		Description:  unprovisioningPeer.Description,
		PreSharedKey: unprovisioningPeer.PreSharedKey,
		PublicKey:    unprovisioningPeer.PublicKey,
		State:        models.ProvisionStateUnprovisioned,
		ProfileId:    unprovisioningPeer.ProfileId,
		TunnelId:     unprovisioningPeer.TunnelId,
		Ip:           unprovisioningPeer.Ip,
		CreationTime: unprovisioningPeer.CreationTime,
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		UpdatePeer(NewPeerMatcher(unprovisionedPeer, t, false, false, false, false)).
		Return(unprovisionedPeer, nil)

	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(2)
	entities.wireguardPeersRepositoryMock.SetGetAllExpected(1)

	entities.peersService.SyncPeers()

	// Wait mock calls
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
}

func TestWireguardPeersServiceImplSyncForceDeletePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	entities := newPeersFsmMockedEntities(t)

	entities.usersServiceMock.EXPECT().GetUsers().Return(entities.userMap, nil)

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     entities.userList[0].Username,
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    entities.profileInfo.Id,
		TunnelId:     entities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialProvisonedPeer}, nil)

	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(entities.tunnelInfo.Id), gomock.Eq(entities.profileInfo.Id)).
		Return(entities.tunnelInfo, entities.profileInfo, nil).
		AnyTimes()

	entities.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&entities.tunnelInfo), gomock.Eq(initialProvisonedPeer.Ip)).Return(nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		DeletePeer(NewPeerMatcher(initialProvisonedPeer, t, false, false, false, false)).
		Return(nil)

	entities.wireguardPeersRepositoryMock.SetDeletePeerExpected(1)
	entities.wireguardPeersRepositoryMock.SetGetAllExpected(1)
	entities.poolServiceMock.SetRemoveIpExpected(1)

	entities.peersService.SyncPeers()

	// Wait mock calls
	entities.wireguardPeersRepositoryMock.Wait(time.Second * 2)
	entities.poolServiceMock.Wait(time.Second * 2)
}
