package handlers

import (
	"github.com/labstack/echo/v4"
	"net/http"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/security"
)

const (
	contextUserKey = "user"
)

type EchoJwtMiddlewareFactory interface {
	BuildMiddleware() echo.MiddlewareFunc
}

type EchoJwtMiddlewareFactoryImpl struct {
	jwtTokenDecoder security.JwtTokenDecoder
}

func NewEchoJwtMiddlewareFactory(jwtTokenDecoder security.JwtTokenDecoder) *EchoJwtMiddlewareFactoryImpl {
	return &EchoJwtMiddlewareFactoryImpl{
		jwtTokenDecoder: jwtTokenDecoder,
	}
}

func (f *EchoJwtMiddlewareFactoryImpl) BuildMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			tokenString := f.getTokenAuth(c)
			if tokenString == "" {
				return &echo.HTTPError{Code: http.StatusUnauthorized, Message: "missing JWT token"}
			}

			user, err := f.jwtTokenDecoder.Decode(tokenString)
			if err == nil {
				// Store user information from token into context.
				c.Set(contextUserKey, user)
				return next(c)
			}

			logging.Logger.Debugw("token validation failed", "token", tokenString, "error", err)

			// Return a generic error to not provide what really happens underneath
			return &echo.HTTPError{Code: http.StatusUnauthorized, Message: "invalid or expired JWT token"}
		}
	}
}

func (f *EchoJwtMiddlewareFactoryImpl) getTokenAuth(c echo.Context) string {
	auth := c.Request().Header.Get("Authorization")

	const authSchemaString = "Bearer"
	schemaLen := len(authSchemaString)
	if len(auth) > schemaLen+1 && auth[:schemaLen] == authSchemaString {
		return auth[schemaLen+1:]
	}
	return ""
}
