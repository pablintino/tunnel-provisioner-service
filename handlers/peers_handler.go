package handlers

import (
	"net/http"
	"tunnel-provisioner-service/dtos"
	"tunnel-provisioner-service/services"
	"tunnel-provisioner-service/utils"

	"github.com/labstack/echo/v4"
)

type peersHandler struct {
	wireguardService services.WireguardService
}

func registerPeersHandler(group *echo.Group, wireguardService services.WireguardService) {
	peersHandler := &peersHandler{
		wireguardService: wireguardService,
	}

	// Register the handler
	group.GET("/tunnels", peersHandler.getTunnelsListHandler)
	group.GET("/tunnels/:id", peersHandler.getTunnelByIdHandler)
	group.GET("/tunnels/:id/profiles", peersHandler.getTunnelProfilesListHandler)
	group.GET("/tunnels/:tid/profiles/:pid", peersHandler.getTunnelProfileByIdHandler)
	group.GET("/tunnels/:tid/profiles/:pid/peers", peersHandler.getTunnelProfilesListHandler)
	group.POST("/tunnels/:tid/profiles/:pid/peers", peersHandler.postTunnelProfilesPeersHandler)

	group.GET("/peers", peersHandler.getPeersListHandler)
	group.GET("/peers/:id", peersHandler.getPeerByIdHandler)
	group.DELETE("/peers/:id", peersHandler.peersDeleteHandler)
	group.PUT("/peers/:id", peersHandler.peersPutHandler)
}

func (h *peersHandler) getPeersListHandler(c echo.Context) error {
	peers, err := h.wireguardService.ListPeers(getUsernameFromContext(c))
	if err != nil {
		return err
	}

	results := make([]dtos.WireguardPeerDto, 0)
	for _, peer := range peers {
		results = append(results, *dtos.ToWireguardPeerDto(peer))
	}
	return c.JSON(http.StatusOK, results)
}

func (h *peersHandler) getTunnelProfilesListHandler(c echo.Context) error {
	tunnelInfo := h.wireguardService.GetTunnelInfo(c.Param("id"))
	if tunnelInfo == nil {
		return c.NoContent(http.StatusNotFound)
	}

	results := make([]dtos.WireguardTunnelProfileDto, 0)
	for _, profile := range tunnelInfo.Profiles {
		results = append(results, *dtos.ToWireguardTunnelProfileDto(&profile))
	}
	return c.JSON(http.StatusOK, results)
}

func (h *peersHandler) postTunnelProfilesPeersHandler(c echo.Context) error {
	var request dtos.WireguardPeerRequestDto
	if err := c.Bind(&request); err != nil {
		return err
	}

	peer, err := h.wireguardService.CreatePeer(
		getUsernameFromContext(c),
		c.Param("tid"),
		c.Param("pid"),
		utils.PointerToEmptyString(request.Description),
		utils.PointerToEmptyString(request.PreSharedKey),
	)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, dtos.ToWireguardPeerDto(peer))
}

func (h *peersHandler) peersPutHandler(c echo.Context) error {

	return nil
}

func (h *peersHandler) getPeerByIdHandler(c echo.Context) error {

	peer, err := h.wireguardService.GetPeer(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}
	if peer == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardPeerDto(peer))
}

func (h *peersHandler) peersDeleteHandler(c echo.Context) error {

	err := h.wireguardService.DeletePeer(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusOK)
}

func (h *peersHandler) getTunnelProfileByIdHandler(c echo.Context) error {
	profileInfo := h.wireguardService.GetProfileInfo(c.Param("tid"), c.Param("pid"))
	if profileInfo == nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelProfileDto(profileInfo))
}

func (h *peersHandler) getTunnelByIdHandler(c echo.Context) error {
	tunnelInfo := h.wireguardService.GetTunnelInfo(c.Param("id"))
	if tunnelInfo == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelDto(tunnelInfo))
}

func (h *peersHandler) getTunnelsListHandler(c echo.Context) error {
	results := make([]dtos.WireguardTunnelDto, 0)
	for _, tunnel := range h.wireguardService.GetTunnels() {
		results = append(results, *dtos.ToWireguardTunnelDto(tunnel))
	}
	return c.JSON(http.StatusOK, results)
}
