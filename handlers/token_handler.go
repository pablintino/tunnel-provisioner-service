package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"time"
	"tunnel-provisioner-service/services"
)

const (
	userProp = "basic-user-prop"
)

type tokenHandler struct {
	usersService services.UsersService
}

func registerTokenHandler(group *echo.Group, usersService services.UsersService) {
	tokenHandler := &tokenHandler{
		usersService: usersService,
	}

	// Register the handler
	group.GET("/token", tokenHandler.tokenHandler, middleware.BasicAuth(tokenHandler.basicAuthValidate))
}

func (h *tokenHandler) tokenHandler(c echo.Context) error {

	user := c.Get(userProp).(string)

	// Set custom claims
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
		Subject:   user,
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func (h *tokenHandler) basicAuthValidate(username, password string, c echo.Context) (bool, error) {
	if h.usersService.Login(username, password) == nil {
		c.Set(userProp, username)
		return true, nil
	}
	return false, nil
}
