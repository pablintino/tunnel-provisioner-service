package services

import (
	"errors"
	"fmt"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/utils"
)

type baseFsmAction struct {
	peer         *models.WireguardPeerModel
	peersService *WireguardPeersServiceImpl
}

func (a *baseFsmAction) sendToError(err error) utils.EventType {
	a.peer.ProvisionStatus = err.Error()
	return peerFsmEventError
}

func (a *baseFsmAction) saveErrorStatus(peer *models.WireguardPeerModel, err error) {
	a.peer.ProvisionStatus = err.Error()
	if _, updateErr := a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); updateErr != nil {
		logging.Logger.Errorw(
			"error saving peer provision status",
			"original-error", err.Error(),
			"update-error", updateErr,
			"peer", peer.Id.Hex(),
		)
	}
}

type peerFsmUnprovisioningAction struct {
	baseFsmAction
}

func (a *peerFsmUnprovisioningAction) Execute(_ utils.EventContext) utils.EventType {
	var err error
	a.peer.State = models.ProvisionStateUnprovisioning
	a.peer.ProvisionStatus = "" // Reset the provision error status string
	if _, err = a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); err != nil {
		return a.sendToError(err)
	}

	return peerFsmEventUnprovision
}

type peerFsmUnprovisionAction struct {
	baseFsmAction
}

func (a *peerFsmUnprovisionAction) Execute(_ utils.EventContext) utils.EventType {
	tunnelInfo, _, err := a.peersService.tunnelService.GetTunnelConfigById(a.peer.TunnelId, a.peer.ProfileId)
	if err != nil {
		return a.sendToError(err)
	}

	provider, found := a.peersService.providers[tunnelInfo.Provider]
	if !found {
		return a.sendToError(fmt.Errorf("provider %s for tunnel %s found", tunnelInfo.Provider, tunnelInfo.Name))
	}

	if len(a.peer.PublicKey) != 0 {
		deleteErr := provider.DeletePeerByPublicKey(&tunnelInfo, a.peer.PublicKey)
		if deleteErr != nil && !errors.Is(deleteErr, ErrProviderPeerNotFound) {
			return a.sendToError(err)
		}
	}

	a.peer.State = models.ProvisionStateUnprovisioned
	a.peer.ProvisionStatus = "" // Reset the provision error status string
	if _, err = a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); err != nil {
		return a.sendToError(err)
	}

	return utils.NoOp
}

type peerFsmProvisioningAction struct {
	baseFsmAction
}

func (a *peerFsmProvisioningAction) Execute(_ utils.EventContext) utils.EventType {
	var err error
	tunnelInfo, _, err := a.peersService.tunnelService.GetTunnelConfigById(a.peer.TunnelId, a.peer.ProfileId)
	if err != nil {
		return a.sendToError(err)
	}

	if a.peer.Ip.IsUnspecified() {
		a.peer.Ip, err = a.peersService.poolService.GetNextIp(&tunnelInfo)
		if err == nil {
			_, err = a.peersService.wireguardPeersRepository.UpdatePeer(a.peer)
		}
	}

	if err != nil {
		return a.sendToError(err)
	}

	a.peer.State = models.ProvisionStateProvisioning
	a.peer.ProvisionStatus = "" // Reset the provision error status string
	if _, err = a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); err != nil {
		return a.sendToError(err)
	}

	// If interface not present when provisioning just go to unprovision
	if !tunnelInfo.Interface.Present {
		return peerFsmEventUnprovision
	}

	return peerFsmEventProvision
}

type peerFsmProvisionAction struct {
	baseFsmAction
}

func (a *peerFsmProvisionAction) provisionPeerWithoutKey(peer *models.WireguardPeerModel,
	tunnelInfo *models.WireguardTunnelInfo,
	tunnelProfileInfo *models.WireguardTunnelProfileInfo,
	provider WireguardTunnelProvider) (*WireguardPeerKeyPair, error) {
	for index := 0; index < wireguardPeerCreationRetries; index++ {
		kp, err := buildWireguardApiPair()
		if err != nil {
			return nil, err
		}

		_, err = provider.CreatePeer(kp.PublicKey, peer.Description, peer.PreSharedKey, tunnelInfo, tunnelProfileInfo, peer.Ip)
		if err != nil && routerOSResourceAlreadyExistsError(routerOSRetrieveApiErrorMessage(err)) {
			// Key already exists
			continue
		} else if err != nil {
			return nil, err
		}
		return kp, nil
	}
	return nil, fmt.Errorf("cannot create peer in %d attempts", wireguardPeerCreationRetries)
}

func (a *peerFsmProvisionAction) Execute(_ utils.EventContext) utils.EventType {

	var err error
	tunnelInfo, profileInfo, err := a.peersService.tunnelService.GetTunnelConfigById(a.peer.TunnelId, a.peer.ProfileId)
	if err != nil {
		return a.sendToError(err)
	}

	provider, found := a.peersService.providers[tunnelInfo.Provider]
	if !found {
		return a.sendToError(fmt.Errorf("provider %s for tunnel %s found", tunnelInfo.Provider, tunnelInfo.Name))
	}

	if len(a.peer.PublicKey) == 0 {
		// Create keys and provision
		var keys *WireguardPeerKeyPair
		keys, err = a.provisionPeerWithoutKey(a.peer, &tunnelInfo, &profileInfo, provider)
		if err == nil {
			// Store the keys to be saved in DB
			a.peer.PublicKey = keys.PublicKey
			a.peer.PrivateKey = keys.PrivateKey
		}

	} else {
		var providerPeer *WireguardProviderPeer
		providerPeer, err = provider.GetPeerByPublicKey(a.peer.PublicKey, &tunnelInfo)
		if err != nil && errors.Is(err, ErrProviderPeerNotFound) {
			// Just create the peer with the stored keys
			_, err = provider.CreatePeer(
				a.peer.PublicKey,
				a.peer.Description,
				a.peer.PreSharedKey,
				&tunnelInfo,
				&profileInfo,
				a.peer.Ip,
			)
		} else if err == nil {
			err = provider.UpdatePeer(
				providerPeer.Id,
				providerPeer.PublicKey,
				a.peer.Description,
				a.peer.PreSharedKey,
				&tunnelInfo,
				&profileInfo,
				a.peer.Ip,
			)
		} else {
			return a.sendToError(err)
		}
	}

	if err == nil {
		a.peer.State = models.ProvisionStateProvisioned
		a.peer.ProvisionStatus = "" // Reset the provision error status string
		_, err = a.peersService.wireguardPeersRepository.UpdatePeer(a.peer)
	}

	if err != nil {
		return a.sendToError(err)
	}

	return utils.NoOp
}

type peerFsmDeletingAction struct {
	baseFsmAction
}

func (a *peerFsmDeletingAction) Execute(_ utils.EventContext) utils.EventType {
	a.peer.State = models.ProvisionStateDeleting
	if _, err := a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); err != nil {
		return a.sendToError(err)
	}

	return peerFsmEventDelete
}

type peerFsmDeleteAction struct {
	baseFsmAction
}

func (a *peerFsmDeleteAction) Execute(_ utils.EventContext) utils.EventType {
	tunnelInfo, _, err := a.peersService.tunnelService.GetTunnelConfigById(a.peer.TunnelId, a.peer.ProfileId)
	if err != nil {
		a.saveErrorStatus(a.peer, err)
		return utils.NoOp
	}

	provider, found := a.peersService.providers[tunnelInfo.Provider]
	if !found {
		a.saveErrorStatus(a.peer, fmt.Errorf("provider %s for tunnel %s found", tunnelInfo.Provider, tunnelInfo.Name))
		return utils.NoOp

	}

	if len(a.peer.PublicKey) != 0 {
		deleteErr := provider.DeletePeerByPublicKey(&tunnelInfo, a.peer.PublicKey)
		if deleteErr != nil && !errors.Is(deleteErr, ErrProviderPeerNotFound) {
			a.saveErrorStatus(a.peer, err)
			return utils.NoOp
		}
	}

	if err := a.peersService.wireguardPeersRepository.DeletePeer(a.peer); err != nil {
		a.saveErrorStatus(a.peer, err)
		return utils.NoOp
	}

	if !a.peer.Ip.IsUnspecified() {
		if err := a.peersService.poolService.RemoveIp(&tunnelInfo, a.peer.Ip); err != nil {
			a.saveErrorStatus(a.peer, err)
		}
	}

	return utils.NoOp
}

type peerFsmForceDeleteAction struct {
	baseFsmAction
}

func (a *peerFsmForceDeleteAction) Execute(_ utils.EventContext) utils.EventType {
	tunnelInfo, _, err := a.peersService.tunnelService.GetTunnelConfigById(a.peer.TunnelId, a.peer.ProfileId)
	if err != nil {
		a.saveErrorStatus(a.peer, err)
		return utils.NoOp
	}

	if err := a.peersService.wireguardPeersRepository.DeletePeer(a.peer); err != nil {
		a.saveErrorStatus(a.peer, err)
		return utils.NoOp
	}

	if !a.peer.Ip.IsUnspecified() {
		if err := a.peersService.poolService.RemoveIp(&tunnelInfo, a.peer.Ip); err != nil {
			a.saveErrorStatus(a.peer, err)
		}
	}

	return utils.NoOp
}

type peerFsmErrorAction struct {
	baseFsmAction
}

func (a *peerFsmErrorAction) Execute(_ utils.EventContext) utils.EventType {
	a.peer.State = models.ProvisionStateError
	if _, err := a.peersService.wireguardPeersRepository.UpdatePeer(a.peer); err != nil {
		logging.Logger.Errorw(
			"error updating peer provision state to error",
			"update-error", err,
			"peer", a.peer.Id.Hex(),
		)
	}
	return utils.NoOp
}

func newPeerFsm(peer *models.WireguardPeerModel, peersService *WireguardPeersServiceImpl) *utils.StateMachine {
	return &utils.StateMachine{
		Current: utils.StateType(peer.State),
		Transitions: utils.Transitions{
			models.ProvisionStateCreated: utils.FSMEventTransitions{
				/* Evt. Provision: Created -> Provisioning */
				peerFsmEventProvision: utils.FSMTransition{Action: &peerFsmProvisioningAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateProvisioning},

				/* Evt. Error: Created -> Error */
				peerFsmEventError: utils.FSMTransition{Action: &peerFsmErrorAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateError},
			},
			models.ProvisionStateUnprovisioned: utils.FSMEventTransitions{
				/* Evt. Provision: Unprovisioned -> Provisioning */
				peerFsmEventProvision: utils.FSMTransition{Action: &peerFsmProvisioningAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateProvisioning},

				/* Evt. Delete: Unprovisioned-> Deleting */
				peerFsmEventDelete: utils.FSMTransition{Action: &peerFsmDeletingAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleting},

				/* Evt. Force Delete: Unprovisioned-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},

				/* Evt. Unprovision: Unprovisioned -> Unprovisioned */
				peerFsmEventUnprovision: utils.FSMTransition{Action: &peerFsmUnprovisionAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateUnprovisioned},

				/* Evt. Error: Unprovisioned -> Error */
				peerFsmEventError: utils.FSMTransition{Action: &peerFsmErrorAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateError},
			},
			models.ProvisionStateProvisioning: utils.FSMEventTransitions{
				/* Evt. Provision: Provisioning -> Provisioned */
				peerFsmEventProvision: utils.FSMTransition{Action: &peerFsmProvisionAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateProvisioned},

				/* Evt. Error: Provisioning -> Error */
				peerFsmEventError: utils.FSMTransition{Action: &peerFsmErrorAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateError},

				/* Evt. Delete: Provisioning -> Deleting */
				peerFsmEventDelete: utils.FSMTransition{Action: &peerFsmDeletingAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleting},

				/* Evt. Force Delete: Provisioning-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},

				/* Evt. Unprovision: Provisioned -> Error */
				peerFsmEventUnprovision: utils.FSMTransition{Action: &peerFsmUnprovisioningAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateUnprovisioning},
			},
			models.ProvisionStateProvisioned: utils.FSMEventTransitions{
				/* Evt. Delete: Provisioned-> Deleting */
				peerFsmEventDelete: utils.FSMTransition{Action: &peerFsmDeletingAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleting},

				/* Evt. Delete: Provisioned-> Provisioned */
				peerFsmEventProvision: utils.FSMTransition{Action: &peerFsmProvisionAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateProvisioned},

				/* Evt. Error: Provisioned -> Error */
				peerFsmEventError: utils.FSMTransition{Action: &peerFsmErrorAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateError},

				/* Evt. Force Delete: Provisioned-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},

				/* Evt. Unprovision: Provisioned -> Unprovisioning */
				peerFsmEventUnprovision: utils.FSMTransition{Action: &peerFsmUnprovisioningAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateUnprovisioning},
			},

			models.ProvisionStateUnprovisioning: utils.FSMEventTransitions{
				/* Evt. Error: Unprovisioning -> Error */
				peerFsmEventError: utils.FSMTransition{Action: &peerFsmErrorAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateError},

				/* Evt. Unprovision: Unprovisioning -> Unprovisioned */
				peerFsmEventUnprovision: utils.FSMTransition{Action: &peerFsmUnprovisionAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateUnprovisioned},

				/* Evt. Force Delete: Unprovisioning-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},
			},
			models.ProvisionStateDeleting: utils.FSMEventTransitions{
				/* Evt. Delete: Deleting-> Deleted */
				peerFsmEventDelete: utils.FSMTransition{Action: &peerFsmDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},

				/* Evt. Force Delete: Deleting-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},
			},
			models.ProvisionStateError: utils.FSMEventTransitions{
				/* Evt. Delete: Error -> Deleting */
				peerFsmEventDelete: utils.FSMTransition{Action: &peerFsmDeletingAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleting},

				/* Evt. Force Delete: Error-> Deleted */
				peerFsmEventForceDelete: utils.FSMTransition{Action: &peerFsmForceDeleteAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateDeleted},

				/* Evt. Provision: Error -> Provisioning */
				peerFsmEventProvision: utils.FSMTransition{Action: &peerFsmProvisioningAction{baseFsmAction{peer: peer, peersService: peersService}}, Target: models.ProvisionStateProvisioning},
			},
		},
	}
}

func (u *WireguardPeersServiceImpl) sendEventToPeerFsm(event utils.EventType, peer *models.WireguardPeerModel) {
	if err := newPeerFsm(peer, u).SendEvent(event, nil); err != nil {
		logging.Logger.Errorw(
			"failed to send event to peer FSM",
			"peer", peer,
			"event", event,
			"error", err.Error(),
		)
	}
}
