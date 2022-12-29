package handlers

import (
	"net/http"
	"tunnel-provisioner-service/dtos"
	"tunnel-provisioner-service/services"

	"github.com/golang-jwt/jwt"
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
	group.GET("/peers", peersHandler.peersGetHandler)
	group.POST("/peers/:id", peersHandler.peersPostHandler)
	group.DELETE("/peers/:id", peersHandler.peersPutHandler)
	group.PUT("/peers/:id", peersHandler.peersDeleteHandler)
}

func (h *peersHandler) peersGetHandler(c echo.Context) error {

	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(*jwt.StandardClaims)
	peers, err := h.wireguardService.ListPeers(claims.Subject)
	if err != nil {
		return err
	}

	results := make([]dtos.WireguardPeerDto, 0)
	for _, peer := range peers {
		results = append(results, *dtos.ToWireguardPeerDto(peer))
	}
	return c.JSON(http.StatusOK, results)
}

func (h *peersHandler) peersPostHandler(c echo.Context) error {

	return nil
}

func (h *peersHandler) peersPutHandler(c echo.Context) error {

	return nil
}

func (h *peersHandler) peersDeleteHandler(c echo.Context) error {

	return nil
}
