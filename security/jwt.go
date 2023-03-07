package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtv2 "github.com/lestrrat-go/jwx/v2/jwt"
	"os"
	"strings"
	"time"
	"tunnel-provisioner-service/config"
)

type JwtSignKeyProvider interface {
	GetSignKey() jwk.Key
	GetPubKey(kid string) jwk.Key
}

type JwtSignKeyProviderImpl struct {
	jwtConfig *config.JWTConfiguration
	keySet    jwk.Set
	signKey   jwk.Key
}

func NewJwtSignKeyProvider(jwtConfig *config.JWTConfiguration) (*JwtSignKeyProviderImpl, error) {
	provider := &JwtSignKeyProviderImpl{
		jwtConfig: jwtConfig,
	}

	if jwtConfig.JKWUrl != "" {
		if err := provider.initializeWithRemoteJwk(); err != nil {
			return nil, err
		}
	} else if jwtConfig.JWTKey == "" {
		provider.initializeWithRandomKey()
	} else {
		if err := provider.initializeWithProvidedKey(); err != nil {
			return nil, err
		}
	}

	return provider, nil
}

func (p *JwtSignKeyProviderImpl) initializeWithRemoteJwk() error {
	cache := jwk.NewCache(context.Background())
	err := cache.Register(p.jwtConfig.JKWUrl, jwk.WithMinRefreshInterval(15*time.Minute))
	if err != nil {
		return err
	}
	p.keySet = jwk.NewCachedSet(cache, p.jwtConfig.JKWUrl)
	return nil
}

func (p *JwtSignKeyProviderImpl) initializeWithRandomKey() {
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err.Error())
	}

	// Encode private key to PEM to store it in memory
	privPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  rsaPrivateKeyHeader,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	privateKey, err := jwk.ParseKey(privPEM, jwk.WithPEM(true))
	if err != nil {
		panic(err.Error())
	}
	if err := jwk.AssignKeyID(privateKey); err != nil {
		panic(err.Error())
	}

	p.signKey = privateKey
	p.keySet = jwk.NewSet()

	if err := p.initKeySetFromPrivateKey(key); err != nil {
		// As PK is generated here format is controlled, and it shouldn't fail
		panic(err.Error())
	}
}

func (p *JwtSignKeyProviderImpl) initKeySetFromPrivateKey(key *rsa.PrivateKey) error {
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  rsaPublicKeyHeader,
			Bytes: x509.MarshalPKCS1PublicKey(key.Public().(*rsa.PublicKey)),
		},
	)

	k, err := jwk.ParseKey(pubPEM, jwk.WithPEM(true))
	if err != nil {
		return err
	}
	if err := jwk.AssignKeyID(k); err != nil {
		return err
	}

	if err := p.keySet.AddKey(k); err != nil {
		return err
	}

	return nil
}

func (p *JwtSignKeyProviderImpl) initializeWithProvidedKey() error {
	// If the data is loaded in configuration wrapped it can contain spaces and line breaks
	sanitizedBase64String := strings.ReplaceAll(p.jwtConfig.JWTKey, "\n", "")
	sanitizedBase64String = strings.ReplaceAll(sanitizedBase64String, " ", "")

	decodedPEMData, err := base64.StdEncoding.DecodeString(sanitizedBase64String)
	if err != nil {
		return errors.New("JWT sign key in not a valid base64 string")
	}

	privatePEM := getPublicKeyFromPEM(decodedPEMData)
	if privatePEM == nil {
		return errors.New("JWT sign key doesn't contain a proper private RSA key in PEM format")
	}

	privateKey, err := jwk.ParseKey(pem.EncodeToMemory(privatePEM), jwk.WithPEM(true))
	if err != nil {
		// Should never reach this as key is generated here and not provided from environment
		return err
	}

	if err := jwk.AssignKeyID(privateKey); err != nil {
		return err
	}

	var privateRSAKey rsa.PrivateKey
	if err := privateKey.Raw(&privateRSAKey); err != nil {
		panic(err.Error())
	}

	p.keySet = jwk.NewSet()
	p.signKey = privateKey
	return p.initKeySetFromPrivateKey(&privateRSAKey)

}

func (p *JwtSignKeyProviderImpl) GetPubKey(kid string) jwk.Key {
	if key, found := p.keySet.LookupKeyID(kid); found {
		return key
	}
	return nil
}

func (p *JwtSignKeyProviderImpl) GetSignKey() jwk.Key {
	return p.signKey
}

type EchoJwtMiddlewareFactory interface {
	BuildMiddleware() echo.MiddlewareFunc
}

type EchoJwtMiddlewareFactoryImpl struct {
	jwtSignKeyProvider JwtSignKeyProvider
}

func NewEchoJwtMiddlewareFactory(jwtSignKeyProvider JwtSignKeyProvider) *EchoJwtMiddlewareFactoryImpl {
	return &EchoJwtMiddlewareFactoryImpl{
		jwtSignKeyProvider: jwtSignKeyProvider,
	}
}

func (f *EchoJwtMiddlewareFactoryImpl) BuildMiddleware() echo.MiddlewareFunc {
	jwtMiddleware := middleware.JWTWithConfig(middleware.JWTConfig{
		KeyFunc: func(token *jwt.Token) (interface{}, error) {
			keyID, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("expecting JWT header to have a key ID in the kid field")
			}

			key := f.jwtSignKeyProvider.GetPubKey(keyID)
			if key == nil {
				return nil, fmt.Errorf("unable to find key %q", keyID)
			}

			var pubKey interface{}
			if err := key.Raw(&pubKey); err != nil {
				return nil, fmt.Errorf("unable to get the public key. Error: %s", err.Error())
			}

			return pubKey, nil
		},
		Claims: &jwt.StandardClaims{},
	})

	return jwtMiddleware
}

type JwtTokenEncoder interface {
	Encode(username string) (string, error)
}

type JwtTokenEncoderImpl struct {
	jwtSignKeyProvider JwtSignKeyProvider
	issuer             string
}

func NewJwtTokenEncoder(jwtSignKeyProvider JwtSignKeyProvider) (*JwtTokenEncoderImpl, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	return &JwtTokenEncoderImpl{
		jwtSignKeyProvider: jwtSignKeyProvider,
		issuer:             hostname,
	}, nil
}

func (f *JwtTokenEncoderImpl) Encode(username string) (string, error) {
	now := time.Now()
	tok, err := jwtv2.NewBuilder().
		Issuer(f.issuer).
		Expiration(now.Add(time.Hour * 72)).
		Subject(username).
		IssuedAt(now).
		Build()
	if err != nil {
		return "", err
	}

	signed, err := jwtv2.Sign(tok, jwtv2.WithKey(jwa.RS256, f.jwtSignKeyProvider.GetSignKey()))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
