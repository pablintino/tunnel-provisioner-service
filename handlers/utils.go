package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"strconv"
)

func getUsernameFromContext(c echo.Context) string {
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(*jwt.StandardClaims)
	return claims.Subject
}

func tryGetIntQueryParam(c echo.Context, name string, defaultValue int) int {
	sizeParam := c.QueryParam(name)
	if sizeParam != "" {
		if size, err := strconv.Atoi(sizeParam); err == nil {
			return size
		}
	}
	return defaultValue
}
