package security

import (
	"tunnel-provisioner-service/config"
)

type Container struct {
	JwtSignKeyProvider       JwtSignKeyProvider
	EchoJwtMiddlewareFactory EchoJwtMiddlewareFactory
	JwtTokenEncoder          JwtTokenEncoder
}

func NewContainer(configuration *config.Config) (*Container, error) {
	jwtSignKeyProvider, err := NewJwtSignKeyProvider(&configuration.Security.JWT)
	if err != nil {
		return nil, err
	}

	jwtTokenEncoder, err := NewJwtTokenEncoder(jwtSignKeyProvider)
	if err != nil {
		return nil, err
	}
	return &Container{
		JwtSignKeyProvider:       jwtSignKeyProvider,
		EchoJwtMiddlewareFactory: NewEchoJwtMiddlewareFactory(jwtSignKeyProvider),
		JwtTokenEncoder:          jwtTokenEncoder,
	}, nil
}
