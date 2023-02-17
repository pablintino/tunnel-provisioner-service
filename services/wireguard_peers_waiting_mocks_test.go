package services_test

import (
	"github.com/golang/mock/gomock"
	"net"
	"sync/atomic"
	"testing"
	"time"
	"tunnel-provisioner-service/models"
)

type WaitingMockWireguardPeersRepository struct {
	mock                       *MockWireguardPeersRepository
	getPeersByUsernameCount    atomic.Uint32
	getPeersByUsernameExpected uint32
	getPeersByTunnelIdCount    atomic.Uint32
	getPeersByTunnelIdExpected uint32
	getPeerByIdCount           atomic.Uint32
	getPeerByIdExpected        uint32
	savePeerCount              atomic.Uint32
	savePeerExpected           uint32
	updatePeerCount            atomic.Uint32
	updatePeerExpected         uint32
	deletePeerCount            atomic.Uint32
	deletePeerExpected         uint32
	getAllCount                atomic.Uint32
	getAllExpected             uint32
	t                          *testing.T
	updateChan                 chan struct{}
}

func (m *WaitingMockWireguardPeersRepository) SetGetPeersByUsernameExpected(expected uint32) {
	m.getPeersByUsernameExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetGetPeersByTunnelIdExpected(expected uint32) {
	m.getPeersByTunnelIdExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetGetPeerByIdExpected(expected uint32) {
	m.getPeerByIdExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetSavePeerExpected(expected uint32) {
	m.savePeerExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetUpdatePeerExpected(expected uint32) {
	m.updatePeerExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetDeletePeerExpected(expected uint32) {
	m.deletePeerExpected = expected
}

func (m *WaitingMockWireguardPeersRepository) SetGetAllExpected(expected uint32) {
	m.getAllExpected = expected
}

func NewWaitingMockWireguardPeersRepository(ctrl *gomock.Controller, t *testing.T) *WaitingMockWireguardPeersRepository {
	return &WaitingMockWireguardPeersRepository{
		mock:       NewMockWireguardPeersRepository(ctrl),
		t:          t,
		updateChan: make(chan struct{}, 1024),
	}
}

func (m *WaitingMockWireguardPeersRepository) EXPECT() *MockWireguardPeersRepositoryMockRecorder {
	return m.mock.EXPECT()
}

func (m *WaitingMockWireguardPeersRepository) GetPeersByUsername(username string) ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeersByUsername(username)
	if m.getPeersByUsernameExpected == 0 {
		m.t.Fatalf("call to GetPeersByUsername not expected")
	}
	m.getPeersByUsernameCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) GetPeersByTunnelId(tunnelId string) ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeersByTunnelId(tunnelId)
	if m.getPeersByTunnelIdExpected == 0 {
		m.t.Fatalf("call to GetPeersByTunnelId not expected")
	}
	m.getPeersByTunnelIdCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) GetPeerById(username, id string) (*models.WireguardPeerModel, error) {
	val, err := m.mock.GetPeerById(username, id)
	if m.getPeerByIdExpected == 0 {
		m.t.Fatalf("call to GetPeerById not expected")
	}
	m.getPeerByIdCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) SavePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	val, err := m.mock.SavePeer(peer)
	if m.savePeerExpected == 0 {
		m.t.Fatalf("call to SavePeer not expected")
	}
	m.savePeerCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) UpdatePeer(peer *models.WireguardPeerModel) (*models.WireguardPeerModel, error) {
	val, err := m.mock.UpdatePeer(peer)
	if m.updatePeerExpected == 0 {
		m.t.Fatalf("call to UpdatePeer not expected")
	}
	m.updatePeerCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) GetAll() ([]*models.WireguardPeerModel, error) {
	val, err := m.mock.GetAll()
	if m.getAllExpected == 0 {
		m.t.Fatalf("call to GetAll not expected")
	}
	m.getAllCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockWireguardPeersRepository) DeletePeer(peer *models.WireguardPeerModel) error {
	err := m.mock.DeletePeer(peer)
	if m.deletePeerExpected == 0 {
		m.t.Fatalf("call to DeletePeer not expected")
	}
	m.deletePeerCount.Add(1)
	m.updateChan <- struct{}{}
	return err
}

func (m *WaitingMockWireguardPeersRepository) isCountReached() bool {

	return m.deletePeerCount.Load() == m.deletePeerExpected &&
		m.updatePeerCount.Load() == m.updatePeerExpected &&
		m.savePeerCount.Load() == m.savePeerExpected &&
		m.getAllCount.Load() == m.getAllExpected &&
		m.getPeersByUsernameCount.Load() == m.getPeersByUsernameExpected &&
		m.getPeerByIdCount.Load() == m.getPeerByIdExpected &&
		m.getPeersByTunnelIdCount.Load() == m.getPeersByTunnelIdExpected

}

func (m *WaitingMockWireguardPeersRepository) Wait(timeout time.Duration) {
	timeoutChan := time.After(timeout)
	for {
		select {
		case <-m.updateChan:
			if m.isCountReached() {
				return
			}
		case <-timeoutChan:
			m.t.Fatalf("WaitingMockWireguardPeersRepository wait timeout")
			return
		}
	}

}

type WaitingMockPoolService struct {
	mock               *MockPoolService
	deletePoolCount    atomic.Uint32
	deletePoolExpected uint32
	getNextIpCount     atomic.Uint32
	getNextIpExpected  uint32
	removeIpCount      atomic.Uint32
	removeIpExpected   uint32
	t                  *testing.T
	updateChan         chan struct{}
}

func NewWaitingMockPoolService(ctrl *gomock.Controller, t *testing.T) *WaitingMockPoolService {
	return &WaitingMockPoolService{
		mock:       NewMockPoolService(ctrl),
		t:          t,
		updateChan: make(chan struct{}, 1024),
	}
}

func (m *WaitingMockPoolService) EXPECT() *MockPoolServiceMockRecorder {
	return m.mock.EXPECT()
}

func (m *WaitingMockPoolService) SetDeletePoolExpected(expected uint32) {
	m.deletePoolExpected = expected
}

func (m *WaitingMockPoolService) SetGetNextIpExpected(expected uint32) {
	m.getNextIpExpected = expected
}

func (m *WaitingMockPoolService) SetRemoveIpExpected(expected uint32) {
	m.removeIpExpected = expected
}

func (m *WaitingMockPoolService) DeletePool(tunnel *models.WireguardTunnelInfo) error {
	err := m.mock.DeletePool(tunnel)
	if m.deletePoolExpected == 0 {
		m.t.Fatalf("call to DeletePool not expected")
	}
	m.deletePoolCount.Add(1)
	m.updateChan <- struct{}{}
	return err
}

func (m *WaitingMockPoolService) GetNextIp(tunnel *models.WireguardTunnelInfo) (net.IP, error) {
	val, err := m.mock.GetNextIp(tunnel)
	if m.getNextIpExpected == 0 {
		m.t.Fatalf("call to GetNextIp not expected")
	}
	m.getNextIpCount.Add(1)
	m.updateChan <- struct{}{}
	return val, err
}

func (m *WaitingMockPoolService) RemoveIp(tunnel *models.WireguardTunnelInfo, ip net.IP) error {
	err := m.mock.RemoveIp(tunnel, ip)
	if m.removeIpExpected == 0 {
		m.t.Fatalf("call to RemoveIp not expected")
	}
	m.removeIpCount.Add(1)
	m.updateChan <- struct{}{}
	return err
}

func (m *WaitingMockPoolService) isCountReached() bool {
	return m.deletePoolCount.Load() == m.deletePoolExpected &&
		m.getNextIpCount.Load() == m.getNextIpExpected &&
		m.removeIpCount.Load() == m.removeIpExpected
}

func (m *WaitingMockPoolService) Wait(timeout time.Duration) {
	timeoutChan := time.After(timeout)
	for {
		select {
		case <-m.updateChan:
			if m.isCountReached() {
				return
			}
		case <-timeoutChan:
			m.t.Fatalf("WaitingMockPoolService wait timeout")
			return
		}
	}

}
