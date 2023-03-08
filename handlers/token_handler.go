package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/security"
	"tunnel-provisioner-service/services"
)

const (
	userProp = "basic-user-prop"
)

type TokenHandler struct {
	usersService    services.UsersService
	jwtTokenEncoder security.JwtTokenEncoder
}

func NewTokenHandler(group *echo.Group, usersService services.UsersService,
	jwtTokenEncoder security.JwtTokenEncoder) *TokenHandler {
	tokenHandler := &TokenHandler{
		usersService:    usersService,
		jwtTokenEncoder: jwtTokenEncoder,
	}

	// Register the handler
	group.GET("/token", tokenHandler.tokenHandler, middleware.BasicAuth(tokenHandler.basicAuthValidate))
	return tokenHandler

}

func (h *TokenHandler) tokenHandler(c echo.Context) error {
	userToken, err := h.jwtTokenEncoder.Encode(c.Get(userProp).(*models.User))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": userToken,
	})
}

func (h *TokenHandler) basicAuthValidate(username, password string, c echo.Context) (bool, error) {
	if userModel, err := h.usersService.Login(username, password); err == nil {
		c.Set(userProp, userModel)
		return true, nil
	}
	return false, nil
}
