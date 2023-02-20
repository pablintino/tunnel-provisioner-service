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
	withIp             net.IP
}

// TODO. This is a non-go CHANGE IT
func NewPeerMatcher(x *models.WireguardPeerModel, t *testing.T, ignorePublickey, ignorePrivatekey, ignoreCreationTime, ignoreId bool, withIp net.IP) PeerMatcher {
	return PeerMatcher{x: x, t: t, ignorePublickey: ignorePublickey, ignorePrivatekey: ignorePrivatekey, ignoreCreationTime: ignoreCreationTime, ignoreId: ignoreId, withIp: withIp}
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
		((e.withIp == nil && !e.x.Ip.Equal(xVal.Ip)) || (e.withIp != nil && !e.withIp.Equal(xVal.Ip))) ||
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

type testServices struct {
	wireguardPeersRepositoryMock *WaitingMockWireguardPeersRepository
	usersServiceMock             *MockUsersService
	tunnelsServiceMock           *MockWireguardTunnelService
	wireguardProviderMock        *MockWireguardTunnelProvider
	poolServiceMock              *WaitingMockPoolService
	peersService                 *services.WireguardPeersServiceImpl
}

func newTestServices(t *testing.T, testDummyEntities *dummyEntities) *testServices {
	ctrl := gomock.NewController(t)
	testServicesInst := &testServices{}
	testServicesInst.wireguardPeersRepositoryMock = NewWaitingMockWireguardPeersRepository(ctrl, t)
	testServicesInst.usersServiceMock = NewMockUsersService(ctrl)
	testServicesInst.tunnelsServiceMock = NewMockWireguardTunnelService(ctrl)
	testServicesInst.wireguardProviderMock = NewMockWireguardTunnelProvider(ctrl)
	testServicesInst.poolServiceMock = NewWaitingMockPoolService(ctrl, t)

	providerMap := map[string]services.WireguardTunnelProvider{
		testDummyEntities.tunnelInfo.Provider: testServicesInst.wireguardProviderMock,
	}
	testServicesInst.peersService = services.NewWireguardPeersService(
		testServicesInst.wireguardPeersRepositoryMock,
		providerMap,
		testServicesInst.poolServiceMock,
		testServicesInst.tunnelsServiceMock,
		testServicesInst.usersServiceMock,
	)
	return testServicesInst
}

type dummyEntities struct {
	tunnelInfo  models.WireguardTunnelInfo
	profileInfo models.WireguardTunnelProfileInfo
	userList    []models.User
	userMap     map[string]models.User
	peerIp      net.IP
}

func newPeersDummyEntities() *dummyEntities {
	testDummyEntities := &dummyEntities{}
	const providerName = "routeros"
	testDummyEntities.userMap = map[string]models.User{
		"test-user-1": {Username: "test-user-1", Email: "testuser1@test.com"},
		"test-user-2": {Username: "test-user-2", Email: "testuser2@test.com"},
	}

	for _, u := range testDummyEntities.userMap {
		testDummyEntities.userList = append(testDummyEntities.userList, u)
	}

	testDummyEntities.peerIp = net.IPv4(192, 168, 177, 2)
	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	testDummyEntities.profileInfo = models.WireguardTunnelProfileInfo{
		Name:   "test-profile",
		Id:     utils.GenerateInternalIdFromString("test-profile"),
		Ranges: []net.IPNet{*net1, *net2, *net3},
	}
	testDummyEntities.tunnelInfo = models.WireguardTunnelInfo{
		Name:      "test-tunnel",
		Id:        utils.GenerateInternalIdFromString("test-tunnel"),
		Provider:  providerName,
		Interface: models.WireguardInterfaceModel{Name: "test-interface", Present: true, Provider: providerName},
	}
	return testDummyEntities
}

func TestWireguardPeersServiceImplCreatePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	testDummyEntities := newPeersDummyEntities()
	entities := newTestServices(t, testDummyEntities)

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
		Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
		AnyTimes()

	mockedSavedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "test-username",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		State:        models.ProvisionStateCreated,
		ProfileId:    testDummyEntities.profileInfo.Id,
		TunnelId:     testDummyEntities.tunnelInfo.Id,
		Ip:           net.IPv4zero,
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		SavePeer(NewPeerMatcher(mockedSavedPeer, t, false, false, true, true, nil)).
		Return(mockedSavedPeer, nil)

	peerIp := net.IPv4(192, 168, 177, 2)
	entities.poolServiceMock.EXPECT().GetNextIp(gomock.Eq(&testDummyEntities.tunnelInfo)).Return(peerIp, nil)

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
		UpdatePeer(NewPeerMatcher(updatePeerResponseIpSave, t, false, false, false, false, nil)).
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
		UpdatePeer(NewPeerMatcher(updatePeerResponseProvisioningSave, t, false, false, false, false, nil)).
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
		UpdatePeer(NewPeerMatcher(updatePeerResponseProvisionedSave, t, true, true, false, false, nil)).
		Return(updatePeerResponseProvisionedSave, nil)

	/* PROVIDER: Prepare for CreatePeer call to provider */
	providerPeer := &services.WireguardProviderPeer{}
	entities.wireguardProviderMock.EXPECT().
		CreatePeer(
			NewAnyWgKeyMatcher(),
			gomock.Eq(updatePeerResponseProvisioningSave.Description),
			gomock.Eq(updatePeerResponseProvisioningSave.PreSharedKey),
			gomock.Eq(&testDummyEntities.tunnelInfo),
			gomock.Eq(&testDummyEntities.profileInfo),
			gomock.Eq(peerIp)).Return(providerPeer, nil)

	// Wait till state goes to provisioned
	entities.wireguardPeersRepositoryMock.SetUpdatePeerExpected(3)
	entities.wireguardPeersRepositoryMock.SetSavePeerExpected(1)
	entities.poolServiceMock.SetGetNextIpExpected(1)

	// Call method under test
	result, err := entities.peersService.CreatePeer(
		mockedSavedPeer.Username,
		testDummyEntities.tunnelInfo.Id,
		testDummyEntities.profileInfo.Id,
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

	testDummyEntities := newPeersDummyEntities()
	entities := newTestServices(t, testDummyEntities)

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelInfo(gomock.Eq(testDummyEntities.tunnelInfo.Id)).
		Return(testDummyEntities.tunnelInfo, nil).
		AnyTimes()

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
		Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
		AnyTimes()

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "test-username",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    testDummyEntities.profileInfo.Id,
		TunnelId:     testDummyEntities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().
		GetPeerById(gomock.Eq(initialProvisonedPeer.Username), gomock.Eq(initialProvisonedPeer.Id.Hex())).
		Return(initialProvisonedPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(initialProvisonedPeer.PublicKey)).Return(nil)

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
		UpdatePeer(NewPeerMatcher(updatePeerResponseDeletingSave, t, false, false, false, false, nil)).
		Return(updatePeerResponseDeletingSave, nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		DeletePeer(NewPeerMatcher(updatePeerResponseDeletingSave, t, false, false, false, false, nil)).
		Return(nil)

	entities.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(initialProvisonedPeer.Ip)).Return(nil)

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

func TestWireguardPeersServiceImplSyncDeletePeer(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	testDummyEntities := newPeersDummyEntities()
	entities := newTestServices(t, testDummyEntities)

	entities.usersServiceMock.EXPECT().GetUsers().Return(testDummyEntities.userMap, nil)

	initialUnprovisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     "non-existing-user",
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    testDummyEntities.profileInfo.Id,
		TunnelId:     testDummyEntities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialUnprovisonedPeer}, nil)
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{testDummyEntities.tunnelInfo.Id: testDummyEntities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
		Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
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
		UpdatePeer(NewPeerMatcher(deletingPeer, t, false, false, false, false, nil)).
		Return(deletingPeer, nil)

	entities.wireguardPeersRepositoryMock.EXPECT().
		DeletePeer(NewPeerMatcher(deletingPeer, t, false, false, false, false, nil)).
		Return(nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(deletingPeer.PublicKey)).
		Return(nil)

	entities.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(deletingPeer.Ip)).Return(nil)

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

	testDummyEntities := newPeersDummyEntities()
	entities := newTestServices(t, testDummyEntities)

	entities.usersServiceMock.EXPECT().GetUsers().Return(testDummyEntities.userMap, nil)

	initialProvisonedPeer := &models.WireguardPeerModel{
		Id:           primitive.NewObjectID(),
		Username:     testDummyEntities.userList[0].Username,
		Description:  "description",
		PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
		PublicKey:    "test-public-key",
		State:        models.ProvisionStateProvisioned,
		ProfileId:    testDummyEntities.profileInfo.Id,
		TunnelId:     testDummyEntities.tunnelInfo.Id,
		Ip:           net.IPv4(192, 168, 177, 2),
		CreationTime: time.Now(),
	}
	entities.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialProvisonedPeer}, nil)

	// Key of this test. Disabled the interface
	testDummyEntities.tunnelInfo.Interface.Present = false
	entities.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{testDummyEntities.tunnelInfo.Id: testDummyEntities.tunnelInfo})

	entities.tunnelsServiceMock.EXPECT().
		GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
		Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
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
		UpdatePeer(NewPeerMatcher(unprovisioningPeer, t, false, false, false, false, nil)).
		Return(unprovisioningPeer, nil)

	entities.wireguardProviderMock.EXPECT().
		DeletePeerByPublicKey(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(unprovisioningPeer.PublicKey)).
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
		UpdatePeer(NewPeerMatcher(unprovisionedPeer, t, false, false, false, false, nil)).
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

	testDummyEntities := newPeersDummyEntities()

	type syncTestCases struct {
		description      string
		initialPeerState models.ProvisioningState
	}
	for _, scenario := range []syncTestCases{
		{
			description:      "force delete from provisioned",
			initialPeerState: models.ProvisionStateProvisioned,
		},
		{
			description:      "force delete from provisioning",
			initialPeerState: models.ProvisionStateProvisioning,
		},
		{
			description:      "force delete from unprovisioned",
			initialPeerState: models.ProvisionStateUnprovisioned,
		},
		{
			description:      "force delete from unprovisioning",
			initialPeerState: models.ProvisionStateUnprovisioning,
		},
		{
			description:      "force delete from error",
			initialPeerState: models.ProvisionStateError,
		},
		{
			description:      "force delete from created",
			initialPeerState: models.ProvisionStateCreated,
		},
		{
			description:      "force delete from deleting",
			initialPeerState: models.ProvisionStateDeleting,
		},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			services := newTestServices(t, testDummyEntities)

			services.usersServiceMock.EXPECT().GetUsers().Return(testDummyEntities.userMap, nil)

			initialProvisonedPeer := &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				PublicKey:    "test-public-key",
				State:        scenario.initialPeerState,
				ProfileId:    testDummyEntities.profileInfo.Id,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				Ip:           net.IPv4(192, 168, 177, 2),
				CreationTime: time.Now(),
			}
			services.wireguardPeersRepositoryMock.EXPECT().GetAll().Return([]*models.WireguardPeerModel{initialProvisonedPeer}, nil)

			services.tunnelsServiceMock.EXPECT().GetTunnels().Return(map[string]models.WireguardTunnelInfo{})

			services.tunnelsServiceMock.EXPECT().
				GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
				Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
				AnyTimes()

			services.poolServiceMock.EXPECT().RemoveIp(gomock.Eq(&testDummyEntities.tunnelInfo), gomock.Eq(initialProvisonedPeer.Ip)).Return(nil)

			services.wireguardPeersRepositoryMock.EXPECT().
				DeletePeer(NewPeerMatcher(initialProvisonedPeer, t, false, false, false, false, nil)).
				Return(nil)

			services.wireguardPeersRepositoryMock.SetDeletePeerExpected(1)
			services.wireguardPeersRepositoryMock.SetGetAllExpected(1)
			services.poolServiceMock.SetRemoveIpExpected(1)

			services.peersService.SyncPeers()

			// Wait mock calls
			services.wireguardPeersRepositoryMock.Wait(time.Second * 2)
			services.poolServiceMock.Wait(time.Second * 2)
		})
	}
}

func TestWireguardPeersServiceImplToProvisionSync(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	testDummyEntities := newPeersDummyEntities()

	type syncTestCases struct {
		description        string
		initialPeer        *models.WireguardPeerModel
		peerExistsInRemote bool
	}
	for _, scenario := range []syncTestCases{
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateCreated,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "created to provisioned",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateError,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "error to provisioned without keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateError,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=",
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "error to provisioned with keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateUnprovisioned,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=",
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync unprovisioned to provisioned with keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateUnprovisioned,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync unprovisioned to provisioned no keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateProvisioning,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				Ip:           testDummyEntities.peerIp, // Provisioning peers already has an IP
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync provisioning to provisioned without keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateProvisioning,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				Ip:           testDummyEntities.peerIp, // Provisioning peers already has an IP
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=",
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: true,
			description:        "sync provisioning to provisioned with keys",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateProvisioning,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				Ip:           testDummyEntities.peerIp, // Provisioning peers already has an IP
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=",
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync provisioning to provisioned with keys but not in provider",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateProvisioned,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				Ip:           testDummyEntities.peerIp,                       // Provisioned peers already has an IP
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=", // Always with keys if already provisioned
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync already provisioned (update)",
		},
		{
			initialPeer: &models.WireguardPeerModel{
				Id:           primitive.NewObjectID(),
				Username:     testDummyEntities.userList[0].Username,
				Description:  "description",
				PreSharedKey: "ivknSU8Bf2uWf/4LerTcOfvvntpFgCYhyOfcIp1N988=",
				State:        models.ProvisionStateProvisioned,
				TunnelId:     testDummyEntities.tunnelInfo.Id,
				ProfileId:    testDummyEntities.profileInfo.Id,
				Ip:           testDummyEntities.peerIp,                       // Provisioned peers already has an IP
				PublicKey:    "RiKzVYkkW+7tK8PC12jH5iYP0IQSX0Wk03GPsmECb1E=", // Always with keys if already provisioned
				PrivateKey:   "OEp/WBwUQ5IM8xTM1jY/chTpX6cKWzJ5HgkcttsoDUo=",
				CreationTime: time.Now(),
			},
			peerExistsInRemote: false,
			description:        "sync already provisioned (update) but not in provider",
		},
	} {
		t.Run(scenario.description, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			wireguardPeersRepositoryMock := NewWaitingMockWireguardPeersRepository(ctrl, t)
			usersServiceMock := NewMockUsersService(ctrl)
			tunnelsServiceMock := NewMockWireguardTunnelService(ctrl)
			wireguardProviderMock := NewMockWireguardTunnelProvider(ctrl)
			poolServiceMock := NewWaitingMockPoolService(ctrl, t)

			peersService := services.NewWireguardPeersService(
				wireguardPeersRepositoryMock,
				map[string]services.WireguardTunnelProvider{
					testDummyEntities.tunnelInfo.Provider: wireguardProviderMock,
				},
				poolServiceMock,
				tunnelsServiceMock,
				usersServiceMock,
			)

			// All syncs should retrieve users, peers and active tunnels and their interfaces to check if UP or removal
			usersServiceMock.EXPECT().GetUsers().Return(testDummyEntities.userMap, nil)
			wireguardPeersRepositoryMock.EXPECT().
				GetAll().
				Return([]*models.WireguardPeerModel{scenario.initialPeer}, nil)
			wireguardPeersRepositoryMock.IncGetAllExpected()

			tunnelsServiceMock.EXPECT().
				GetTunnels().
				Return(map[string]models.WireguardTunnelInfo{testDummyEntities.tunnelInfo.Id: testDummyEntities.tunnelInfo})

			tunnelsServiceMock.EXPECT().
				GetTunnelConfigById(gomock.Eq(testDummyEntities.tunnelInfo.Id), gomock.Eq(testDummyEntities.profileInfo.Id)).
				Return(testDummyEntities.tunnelInfo, testDummyEntities.profileInfo, nil).
				AnyTimes()

			providerPeer := &services.WireguardProviderPeer{
				PublicKey:      scenario.initialPeer.PublicKey,
				Disabled:       false,
				Id:             "*1D",
				Description:    scenario.initialPeer.Description,
				AllowedAddress: testDummyEntities.profileInfo.Ranges,
			}

			peerIp := scenario.initialPeer.Ip
			if scenario.initialPeer.Ip == nil || scenario.initialPeer.Ip.IsUnspecified() {
				poolServiceMock.EXPECT().
					GetNextIp(gomock.Eq(&testDummyEntities.tunnelInfo)).
					Return(testDummyEntities.peerIp, nil)
				poolServiceMock.SetGetNextIpExpected(1)
				peerIp = testDummyEntities.peerIp

				// Intermediate save after acquiring an IP
				ipSavePeer := *scenario.initialPeer
				ipSavePeer.Ip = peerIp
				wireguardPeersRepositoryMock.EXPECT().
					UpdatePeer(NewPeerMatcher(&ipSavePeer, t,
						// Ignore keys if starting from a peer without key // TODO Improve to check that a key is passed, ignoring it is a too much simple approach
						len(scenario.initialPeer.PublicKey) == 0,
						len(scenario.initialPeer.PrivateKey) == 0,
						false,
						false, peerIp)).
					Return(&ipSavePeer, nil)
				wireguardPeersRepositoryMock.IncUpdatePeerExpected()
			}

			if len(scenario.initialPeer.PublicKey) == 0 {
				// Expect build from scratch
				wireguardProviderMock.EXPECT().
					CreatePeer(
						NewAnyWgKeyMatcher(),
						gomock.Eq(scenario.initialPeer.Description),
						gomock.Eq(scenario.initialPeer.PreSharedKey),
						gomock.Eq(&testDummyEntities.tunnelInfo),
						gomock.Eq(&testDummyEntities.profileInfo),
						gomock.Eq(peerIp)).Return(providerPeer, nil)
			} else {
				// As a key exists we will check the provider before
				providerGetPeerCall := wireguardProviderMock.EXPECT().
					GetPeerByPublicKey(gomock.Eq(providerPeer.PublicKey), gomock.Eq(&testDummyEntities.tunnelInfo))
				if scenario.peerExistsInRemote {
					providerGetPeerCall.Return(providerPeer, nil)

					wireguardProviderMock.EXPECT().
						UpdatePeer(
							gomock.Eq(providerPeer.Id),
							gomock.Eq(scenario.initialPeer.PublicKey),
							gomock.Eq(scenario.initialPeer.Description),
							gomock.Eq(scenario.initialPeer.PreSharedKey),
							gomock.Eq(&testDummyEntities.tunnelInfo),
							gomock.Eq(&testDummyEntities.profileInfo),
							gomock.Eq(peerIp),
						).
						Return(nil)
				} else {
					providerGetPeerCall.Return(nil, services.ErrProviderPeerNotFound)
					// Public key exists in peer, but it's not present at the provider
					wireguardProviderMock.EXPECT().
						CreatePeer(
							gomock.Eq(scenario.initialPeer.PublicKey),
							gomock.Eq(scenario.initialPeer.Description),
							gomock.Eq(scenario.initialPeer.PreSharedKey),
							gomock.Eq(&testDummyEntities.tunnelInfo),
							gomock.Eq(&testDummyEntities.profileInfo),
							gomock.Eq(peerIp)).Return(providerPeer, nil)
				}
			}

			// Peers that are already provisioned or in provisioning needs to go through the provisioning state
			if scenario.initialPeer.State != models.ProvisionStateProvisioning && scenario.initialPeer.State != models.ProvisionStateProvisioned {
				// Peer should pass PROVISIONING before getting PROVISIONED
				intermediatePeer := *scenario.initialPeer
				intermediatePeer.State = models.ProvisionStateProvisioning
				wireguardPeersRepositoryMock.EXPECT().
					UpdatePeer(NewPeerMatcher(&intermediatePeer, t,
						// Ignore keys if starting from a peer without key // TODO Improve to check that a key is passed, ignoring it is a too much simple approach
						len(scenario.initialPeer.PublicKey) == 0,
						len(scenario.initialPeer.PrivateKey) == 0,
						false,
						false, peerIp)).
					Return(&intermediatePeer, nil)
				wireguardPeersRepositoryMock.IncUpdatePeerExpected()
			}

			// Last update from PROVISIONING to PROVISIONED
			lastPeer := *scenario.initialPeer
			lastPeer.State = models.ProvisionStateProvisioned
			wireguardPeersRepositoryMock.EXPECT().
				UpdatePeer(NewPeerMatcher(&lastPeer, t,
					// Ignore keys if starting from a peer without key // TODO Improve to check that a key is passed, ignoring it is a too much simple approach
					len(scenario.initialPeer.PublicKey) == 0,
					len(scenario.initialPeer.PrivateKey) == 0,
					false,
					false, peerIp)).
				Return(&lastPeer, nil)
			wireguardPeersRepositoryMock.IncUpdatePeerExpected()

			// Call the function under test
			peersService.SyncPeers()

			// Wait till last update is done
			wireguardPeersRepositoryMock.Wait(time.Second * 2)
			poolServiceMock.Wait(time.Second * 2)
		})
	}
}
