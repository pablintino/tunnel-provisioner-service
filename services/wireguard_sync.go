package services

import (
	"time"
	"tunnel-provisioner-service/logging"
)

type WireguardSyncService interface {
	DisposableService
	BooteableService
}

type WireguardSyncServiceImpl struct {
	BooteableService
	DisposableService
	tunnelService WireguardTunnelService
	peersService  WireguardPeersService
	syncPeriod    time.Duration
	timer         *time.Ticker
	closing       chan bool
}

func NewWireguardSyncService(
	peersService WireguardPeersService,
	tunnelService WireguardTunnelService,
	syncPeriodMs uint64,
) *WireguardSyncServiceImpl {
	return &WireguardSyncServiceImpl{
		peersService:  peersService,
		tunnelService: tunnelService,
		closing:       make(chan bool),
		syncPeriod:    time.Duration(syncPeriodMs) * time.Millisecond,
	}
}

func (s *WireguardSyncServiceImpl) OnBoot() error {
	if err := s.handleWireguardSyncTask(); err != nil {
		return err
	}
	s.timer = time.NewTicker(s.syncPeriod)
	go s.syncTask()
	return nil
}

func (s *WireguardSyncServiceImpl) OnClose() {
	if s.timer != nil {
		s.timer.Stop()
		s.closing <- true
	}
}

func (s *WireguardSyncServiceImpl) syncTask() {
	for {
		select {
		case _, ok := <-s.timer.C:
			if !ok {
				return
			}
			if err := s.handleWireguardSyncTask(); err != nil {
				logging.Logger.Errorw(
					"failed to sync service information",
					"error", err.Error(),
				)
			}
		case <-s.closing:
			return
		}
	}
}

func (s *WireguardSyncServiceImpl) handleWireguardSyncTask() error {
	err := s.tunnelService.RefreshTunnelInterfacesInformation()
	if err != nil {
		logging.Logger.Errorw(
			"failed to sync service information",
			"error", err.Error(),
		)
	}

	s.peersService.SyncPeers()

	return nil
}
