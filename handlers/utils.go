package handlers

import (
	"github.com/labstack/echo/v4"
	"strconv"
	"tunnel-provisioner-service/models"
)

func getUsernameFromContext(c echo.Context) string {
	contextUser := c.Get(contextUserKey).(*models.User)
	return contextUser.Username
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
