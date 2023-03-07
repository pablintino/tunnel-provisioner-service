package security

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"strings"
	"time"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/models"
)

type JwtSignKeyProvider interface {
	GetSignKey() jwk.Key
	GetKeySet() jwk.Set
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

	var err error = nil
	if jwtConfig.JWKSUrl != "" {
		err = provider.initializeWithRemoteJwk()
	} else if jwtConfig.JWTValidationKey != "" {
		err = provider.initializeWithProvidedSignKey()
	} else if jwtConfig.JWTSignPrivateKey != "" {
		err = provider.initializeWithProvidedPrivateKey()
	} else {
		provider.initializeWithRandomKey()
	}

	if err != nil {
		return nil, err
	}

	return provider, nil
}

func (p *JwtSignKeyProviderImpl) initializeWithRemoteJwk() error {
	cache := jwk.NewCache(context.Background())
	err := cache.Register(p.jwtConfig.JWKSUrl, jwk.WithMinRefreshInterval(15*time.Minute))
	if err != nil {
		return err
	}
	p.keySet = jwk.NewCachedSet(cache, p.jwtConfig.JWKSUrl)
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
			Type:  pemBlockTypeRsaPrivateKeyHeader,
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
			Type:  pemBlockTypeRsaPublicKeyHeader,
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

func (p *JwtSignKeyProviderImpl) initializeWithProvidedPrivateKey() error {
	privateKey, err := p.getKeyFromEncodedData(p.jwtConfig.JWTSignPrivateKey, pemBlockTypeRsaPrivateKeyHeader)
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

func (p *JwtSignKeyProviderImpl) initializeWithProvidedSignKey() error {
	publicKey, err := p.getKeyFromEncodedData(p.jwtConfig.JWTValidationKey, pemBlockTypeRsaPublicKeyHeader)
	if err != nil {
		return err
	}

	if err := jwk.AssignKeyID(publicKey); err != nil {
		return err
	}

	p.keySet = jwk.NewSet()
	return p.keySet.AddKey(publicKey)
}

func (p *JwtSignKeyProviderImpl) getKeyFromEncodedData(encodedKey string, pemType pemBlockType) (jwk.Key, error) {
	// If the data is loaded in configuration wrapped it can contain spaces and line breaks
	sanitizedBase64String := strings.ReplaceAll(encodedKey, "\n", "")
	sanitizedBase64String = strings.ReplaceAll(sanitizedBase64String, " ", "")

	decodedPEMData, err := base64.StdEncoding.DecodeString(sanitizedBase64String)
	if err != nil {
		return nil, errors.New("JWT key in not a valid base64 string")
	}

	pemData := getPemContentBlock(decodedPEMData, pemType)
	if pemData == nil {
		return nil, errors.New("JWT key doesn't contain a proper RSA key in PEM format")
	}

	jwtKey, err := jwk.ParseKey(pem.EncodeToMemory(pemData), jwk.WithPEM(true))
	if err != nil {
		return nil, err
	}

	return jwtKey, err
}

func (p *JwtSignKeyProviderImpl) GetKeySet() jwk.Set {
	return p.keySet
}

func (p *JwtSignKeyProviderImpl) GetSignKey() jwk.Key {
	return p.signKey
}

type JwtTokenEncoder interface {
	Encode(username string) (string, error)
}

type JwtTokenEncoderImpl struct {
	jwtSignKeyProvider JwtSignKeyProvider
	jwtConfig          *config.JWTConfiguration
	expiration         time.Duration
}

func NewJwtTokenEncoder(jwtSignKeyProvider JwtSignKeyProvider, jwtConfig *config.JWTConfiguration) *JwtTokenEncoderImpl {
	expiration := time.Hour * 72
	if jwtConfig.SignExpirationTime != 0 {
		expiration = time.Duration(jwtConfig.SignExpirationTime) * time.Millisecond
	}

	return &JwtTokenEncoderImpl{
		jwtSignKeyProvider: jwtSignKeyProvider,
		jwtConfig:          jwtConfig,
		expiration:         expiration,
	}
}

func (f *JwtTokenEncoderImpl) Encode(username string) (string, error) {
	now := time.Now()
	tokenBuilder := jwt.NewBuilder().
		Expiration(now.Add(f.expiration)).
		Subject(username).
		IssuedAt(now)

	if f.jwtConfig.UsernameClaim != "" {
		tokenBuilder = tokenBuilder.Claim(f.jwtConfig.UsernameClaim, username)
	}

	// Hardcode audience if specified in configuration
	if f.jwtConfig.Audience != "" {
		tokenBuilder = tokenBuilder.Audience([]string{f.jwtConfig.Audience})
	}

	// Hardcode issuer if specified in configuration
	if f.jwtConfig.Issuer != "" {
		tokenBuilder = tokenBuilder.Issuer(f.jwtConfig.Issuer)
	}

	token, err := tokenBuilder.Build()
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, f.jwtSignKeyProvider.GetSignKey()))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

type JwtTokenDecoder interface {
	Decode(token string) (*models.User, error)
}

type JwtTokenDecoderImpl struct {
	jwtSignKeyProvider JwtSignKeyProvider
	jwtConfig          *config.JWTConfiguration
}

func NewJwtTokenDecoderImpl(jwtSignKeyProvider JwtSignKeyProvider, jwtConfig *config.JWTConfiguration) *JwtTokenDecoderImpl {
	return &JwtTokenDecoderImpl{
		jwtSignKeyProvider: jwtSignKeyProvider,
		jwtConfig:          jwtConfig,
	}
}

func (d *JwtTokenDecoderImpl) Decode(tokenString string) (*models.User, error) {
	token, err := d.parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	userModel := &models.User{}

	// Parse user, mandatory
	if d.jwtConfig.UsernameClaim == "" {
		userModel.Username = token.Subject()
	} else if username, ok := d.getTokenClaimAsString(token, d.jwtConfig.UsernameClaim); ok {
		userModel.Username = username
	}

	if userModel.Username == "" {
		return nil, errors.New("cannot decode username from JWT string claims")
	}

	// Parse email, if available
	usernameClaim := "email"
	if d.jwtConfig.EmailClaim != "" {
		usernameClaim = d.jwtConfig.EmailClaim
	}
	if email, ok := d.getTokenClaimAsString(token, usernameClaim); ok {
		userModel.Email = email
	}

	return userModel, nil
}

func (d *JwtTokenDecoderImpl) getTokenClaimAsString(token jwt.Token, claim string) (string, bool) {
	if val, ok := token.PrivateClaims()[claim]; ok {
		if strVal, typeOk := val.(string); typeOk {
			return strVal, true
		}
	}
	return "", false
}

func (d *JwtTokenDecoderImpl) parseToken(tokenString string) (jwt.Token, error) {
	token := jwt.New()

	options := []jwt.ParseOption{
		jwt.WithToken(token),
		jwt.WithKeySet(d.jwtSignKeyProvider.GetKeySet()),
		jwt.WithValidate(true),
	}

	if d.jwtConfig.Audience != "" {
		options = append(options, jwt.WithAudience(d.jwtConfig.Audience))
	}

	if d.jwtConfig.Issuer != "" {
		options = append(options, jwt.WithIssuer(d.jwtConfig.Issuer))
	}

	if _, err := jwt.ParseString(tokenString, options...); err != nil {
		return nil, err
	}
	return token, nil
}
