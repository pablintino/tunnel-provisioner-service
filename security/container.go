package security

import (
	"crypto/x509"
	"tunnel-provisioner-service/config"
)

type Container struct {
	JwtSignKeyProvider JwtSignKeyProvider
	JwtTokenEncoder    JwtTokenEncoder
	JwtTokenDecoder    JwtTokenDecoder
	TLSCustomCAs       *x509.CertPool
}

func NewContainer(configuration *config.Config) (*Container, error) {
	var err error
	var tlsCustomCAs *x509.CertPool = nil
	if configuration.Security.CustomCAsPath != "" {
		tlsCustomCAs, err = NewTLSCustomCAs(configuration.Security.CustomCAsPath)
		if err != nil {
			return nil, err
		}
	}

	jwtSignKeyProvider, err := NewJwtSignKeyProvider(&configuration.Security.JWT, tlsCustomCAs)
	if err != nil {
		return nil, err
	}

	return &Container{
		JwtSignKeyProvider: jwtSignKeyProvider,
		JwtTokenEncoder:    NewJwtTokenEncoder(jwtSignKeyProvider, &configuration.Security.JWT),
		JwtTokenDecoder:    NewJwtTokenDecoderImpl(jwtSignKeyProvider, &configuration.Security.JWT),
		TLSCustomCAs:       tlsCustomCAs,
	}, nil
}
