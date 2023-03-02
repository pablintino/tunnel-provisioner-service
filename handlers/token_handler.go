package handlers

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"tunnel-provisioner-service/security"
	"tunnel-provisioner-service/services"
)

const (
	userProp = "basic-user-prop"
)

type TokenHandler struct {
	usersService services.UsersService
}

func NewTokenHandler(group *echo.Group, usersService services.UsersService) *TokenHandler {
	tokenHandler := &TokenHandler{
		usersService: usersService,
	}

	// Register the handler
	group.GET("/token", tokenHandler.tokenHandler, middleware.BasicAuth(tokenHandler.basicAuthValidate))
	return tokenHandler

}

func (h *TokenHandler) tokenHandler(c echo.Context) error {

	user := c.Get(userProp).(string)

	userToken, err := security.BuildUserToken(user)
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": userToken,
	})
}

func (h *TokenHandler) basicAuthValidate(username, password string, c echo.Context) (bool, error) {
	if h.usersService.Login(username, password) == nil {
		c.Set(userProp, username)
		return true, nil
	}
	return false, nil
}
