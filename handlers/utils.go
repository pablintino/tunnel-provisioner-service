package handlers

import (
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

func getUsernameFromContext(c echo.Context) string {
	token := c.Get("user").(*jwt.Token)
	claims := token.Claims.(*jwt.StandardClaims)
	return claims.Subject
}
