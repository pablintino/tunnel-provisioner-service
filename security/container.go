package security

import (
	"tunnel-provisioner-service/config"
)

type Container struct {
	JwtSignKeyProvider JwtSignKeyProvider
	JwtTokenEncoder    JwtTokenEncoder
	JwtTokenDecoder    JwtTokenDecoder
}

func NewContainer(configuration *config.Config) (*Container, error) {
	jwtSignKeyProvider, err := NewJwtSignKeyProvider(&configuration.Security.JWT)
	if err != nil {
		return nil, err
	}

	return &Container{
		JwtSignKeyProvider: jwtSignKeyProvider,
		JwtTokenEncoder:    NewJwtTokenEncoder(jwtSignKeyProvider, &configuration.Security.JWT),
		JwtTokenDecoder:    NewJwtTokenDecoderImpl(jwtSignKeyProvider, &configuration.Security.JWT),
	}, nil
}
