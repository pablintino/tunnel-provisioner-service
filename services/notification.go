package services

import "tunnel-provisioner-service/models"

type NotificationService interface {
	NotifyPeerChange(peer models.WireguardPeerModel) error
}

type NotificationServiceImpl struct {
}

func NewNotificationService() *NotificationServiceImpl {
	return &NotificationServiceImpl{}
}

func (s *NotificationServiceImpl) NotifyPeerChange(peer models.WireguardPeerModel) error {
	return nil
}
