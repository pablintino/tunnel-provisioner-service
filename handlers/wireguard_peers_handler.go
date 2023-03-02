package handlers

import (
	"errors"
	"net/http"
	"tunnel-provisioner-service/dtos"
	"tunnel-provisioner-service/services"
	"tunnel-provisioner-service/utils"

	"github.com/labstack/echo/v4"
)

type WireguardPeersHandler struct {
	wireguardService services.WireguardPeersService
	tunnelService    services.WireguardTunnelService
}

func NewWireguardPeersHandler(
	group *echo.Group,
	wireguardService services.WireguardPeersService,
	tunnelService services.WireguardTunnelService,
	middleware ...echo.MiddlewareFunc,
) *WireguardPeersHandler {
	wgGroup := group.Group("/wireguard", middleware...)

	peersHandler := &WireguardPeersHandler{
		wireguardService: wireguardService,
		tunnelService:    tunnelService,
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
	wgGroup.GET("/peers/:id/qr", peersHandler.getPeerQrByIdHandler)
	wgGroup.DELETE("/peers/:id", peersHandler.peersDeleteHandler)
	wgGroup.PUT("/peers/:id", peersHandler.peersPutHandler)

	return peersHandler
}

func (h *WireguardPeersHandler) getPeersListHandler(c echo.Context) error {
	peers, err := h.wireguardService.GetAggregatedPeersByUsername(getUsernameFromContext(c))
	if err != nil {
		return err
	}

	results := make([]dtos.WireguardPeerDto, 0)
	for _, peer := range peers {
		results = append(results, *dtos.ToWireguardPeerDto(peer))
	}
	return c.JSON(http.StatusOK, results)
}

func (h *WireguardPeersHandler) getTunnelProfilesListHandler(c echo.Context) error {
	tunnelInfo, err := h.tunnelService.GetTunnelInfo(c.Param("id"))
	if err != nil && errors.Is(err, services.ErrServiceNotFoundEntity) {
		return c.NoContent(http.StatusNotFound)
	} else if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	results := make([]dtos.WireguardTunnelProfileDto, 0)
	for _, profile := range tunnelInfo.Profiles {
		results = append(results, *dtos.ToWireguardTunnelProfileDto(&profile))
	}
	return c.JSON(http.StatusOK, results)
}

func (h *WireguardPeersHandler) postTunnelProfilesPeersHandler(c echo.Context) error {
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

func (h *WireguardPeersHandler) peersPutHandler(c echo.Context) error {
	// TODO
	return nil
}

func (h *WireguardPeersHandler) getPeerQrByIdHandler(c echo.Context) error {
	const defaultSize = 256
	qrBytes, err := h.wireguardService.GetPeerConfigQr(
		getUsernameFromContext(c),
		c.Param("id"),
		utils.Max(defaultSize, tryGetIntQueryParam(c, "size", defaultSize)),
	)
	if err != nil {
		return err
	}
	if qrBytes == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.Blob(http.StatusOK, "image/png", qrBytes)
}

func (h *WireguardPeersHandler) getPeerByIdHandler(c echo.Context) error {

	peer, err := h.wireguardService.GetAggregatedPeerByUsernameAndId(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}
	if peer == nil {
		return c.NoContent(http.StatusNotFound)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardPeerDto(peer))
}

func (h *WireguardPeersHandler) peersDeleteHandler(c echo.Context) error {

	err := h.wireguardService.DeletePeer(getUsernameFromContext(c), c.Param("id"))
	if err != nil {
		return err
	}

	return c.NoContent(http.StatusOK)
}

func (h *WireguardPeersHandler) getTunnelProfileByIdHandler(c echo.Context) error {
	profileInfo, err := h.tunnelService.GetProfileInfo(c.Param("tid"), c.Param("pid"))
	if err != nil && errors.Is(err, services.ErrServiceNotFoundEntity) {
		return c.NoContent(http.StatusNotFound)
	} else if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelProfileDto(&profileInfo))
}

func (h *WireguardPeersHandler) getTunnelByIdHandler(c echo.Context) error {
	tunnelInfo, err := h.tunnelService.GetTunnelInfo(c.Param("id"))
	if err != nil && errors.Is(err, services.ErrServiceNotFoundEntity) {
		return c.NoContent(http.StatusNotFound)
	} else if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, dtos.ToWireguardTunnelDto(&tunnelInfo))
}

func (h *WireguardPeersHandler) getTunnelsListHandler(c echo.Context) error {
	results := make([]dtos.WireguardTunnelDto, 0)
	for _, tunnel := range h.tunnelService.GetTunnels() {
		results = append(results, *dtos.ToWireguardTunnelDto(&tunnel))
	}
	return c.JSON(http.StatusOK, results)
}
