package handlers

import (
	"net/http"
	"tunnel-provisioner-service/dtos"
	"tunnel-provisioner-service/services"
	"tunnel-provisioner-service/utils"

	"github.com/labstack/echo/v4"
)

type wireguardPeersHandler struct {
	wireguardService services.WireguardService
}

func registerWireguardPeersHandler(group *echo.Group, wireguardService services.WireguardService, middleware ...echo.MiddlewareFunc) {
	wgGroup := group.Group("/wireguard", middleware...)

	peersHandler := &wireguardPeersHandler{
		wireguardService: wireguardService,
	}

	// Register the handler
	wgGroup.GET("/tunnels", peersHandler.getTunnelsListHandler)
	wgGroup.GET("/tunnels/:id", peersHandler.getTunnelByIdHandler)
	wgGroup.GET("/tunnels/:id/profiles", peersHandler.getTunnelProfilesListHandler)
	wgGroup.GET("/tunnels/:tid/profiles/:pid", peersHandler.getTunnelProfileByIdHandler)
	wgGroup.GET("/tunnels/:tid/profiles/:pid/peers", peersHandler.getTunnelProfilesListHandler)
	wgGroup.POST("/tunnels/:tid/profiles/:pid/peers", peersHandler.postTunnelProfilesPeersHandler)

	wgGroup.GET("/peers", peersHandler.getPeersListHandler)
	wgGroup.GET("/peers/:id", peersHandler.getPeerByIdHandler)
	wgGroup.DELETE("/peers/:id", peersHandler.peersDeleteHandler)
	wgGroup.PUT("/peers/:id", peersHandler.peersPutHandler)
}

func (h *wireguardPeersHandler) getPeersListHandler(c echo.Context) error {
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

func (h *wireguardPeersHandler) getTunnelProfilesListHandler(c echo.Context) error {
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

func (h *wireguardPeersHandler) postTunnelProfilesPeersHandler(c echo.Context) error {
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

func (h *wireguardPeersHandler) peersPutHandler(c echo.Context) error {
	// TODO
	return nil
}

func (h *wireguardPeersHandler) getPeerByIdHandler(c echo.Context) error {

	peer, err := h.wireguardService.GetPeer(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}
	if peer == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardPeerDto(peer))
}

func (h *wireguardPeersHandler) peersDeleteHandler(c echo.Context) error {

	err := h.wireguardService.DeletePeer(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusOK)
}

func (h *wireguardPeersHandler) getTunnelProfileByIdHandler(c echo.Context) error {
	profileInfo := h.wireguardService.GetProfileInfo(c.Param("tid"), c.Param("pid"))
	if profileInfo == nil {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelProfileDto(profileInfo))
}

func (h *wireguardPeersHandler) getTunnelByIdHandler(c echo.Context) error {
	tunnelInfo := h.wireguardService.GetTunnelInfo(c.Param("id"))
	if tunnelInfo == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelDto(tunnelInfo))
}

func (h *wireguardPeersHandler) getTunnelsListHandler(c echo.Context) error {
	results := make([]dtos.WireguardTunnelDto, 0)
	for _, tunnel := range h.wireguardService.GetTunnels() {
		results = append(results, *dtos.ToWireguardTunnelDto(tunnel))
	}
	return c.JSON(http.StatusOK, results)
}
