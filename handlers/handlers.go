package handlers

import (
	"tunnel-provisioner-service/services"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func Register(echo *echo.Echo, usersService services.UsersService, wireguardService services.WireguardService) {
	apiGroup := echo.Group("/api/v1")

	registerTokenHandler(apiGroup, usersService)

	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		SigningKey: []byte("secret"),
		Claims:     &jwt.StandardClaims{},
	})

	registerWireguardPeersHandler(apiGroup, wireguardService, jwtMiddleware)

}
