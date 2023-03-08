package config

import (
	"errors"
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/mitchellh/mapstructure"
	"net"
	"net/url"
	"strings"
)

type LDAPConfiguration struct {
	LdapURL        string `koanf:"url"`
	BaseDN         string `koanf:"baseDn"`
	BindUser       string `koanf:"bindUser"`
	BindPassword   string `koanf:"bindPassword"`
	UserFilter     string `koanf:"userFilter"`
	UserClass      string `koanf:"userClass"`
	UserAttribute  string `koanf:"userAttribute"`
	EmailAttribute string `koanf:"emailAttribute"`
	SkipVerify     bool   `koanf:"skipVerify"`
	StartTLS       bool   `koanf:"startTLS"`
}

func (c LDAPConfiguration) validate() error {
	ldapUrl, err := url.Parse(c.LdapURL)
	if err != nil {
		return errors.New("LDAP url must be a valid URL")
	}

	if ldapUrl.Host == "" {
		return errors.New("LDAP url host cannot be empty")
	}

	if ldapUrl.Scheme != "ldap" && ldapUrl.Scheme != "ldaps" {
		return errors.New("LDAP url schema must be one of ldap or ldaps")
	}

	if c.BaseDN == "" {
		return errors.New("LDAP baseDn must be provided")
	}

	if c.BindUser == "" {
		return errors.New("LDAP bindUser must be provided")
	}

	if c.UserClass == "" {
		return errors.New("LDAP userClass must be provided")
	}

	if c.UserAttribute == "" {
		return errors.New("LDAP userAttribute must be provided")
	}

	return nil
}

type WireguardTunnelProfileConfiguration struct {
	Ranges []net.IPNet `koanf:"ranges"`
}

type WireguardTunnelConfiguration struct {
	Profiles  map[string]WireguardTunnelProfileConfiguration `koanf:"profiles"`
	Interface string                                         `koanf:"interface"`
	DNSs      []net.IP                                       `koanf:"dns-servers"`
}

type RouterOSProviderConfig struct {
	Host                    string                                  `koanf:"host"`
	Port                    uint16                                  `koanf:"port"`
	Username                string                                  `koanf:"username"`
	Password                string                                  `koanf:"password"`
	TunnelEndpoint          string                                  `koanf:"tunnels-endpoint"`
	TunnelEndpointInterface string                                  `koanf:"tunnels-endpoint-interface"`
	WireguardTunnels        map[string]WireguardTunnelConfiguration `koanf:"wg-tunnels"`
}

func (c RouterOSProviderConfig) validate() error {
	if c.Host == "" {
		return errors.New("RouterOS provider host must be provided")
	}

	if c.Port == 0 {
		return errors.New("RouterOS provider port must be provided")
	}

	if c.Username == "" {
		return errors.New("RouterOS username host must be provided")
	}

	if c.Password == "" {
		return errors.New("RouterOS password must be provided")
	}

	if len(c.TunnelEndpoint) != 0 && len(c.TunnelEndpointInterface) != 0 {
		return errors.New("only one of tunnels-endpoint or tunnels-endpoint-interface can be provided")
	}
	if len(c.TunnelEndpoint) != 0 {
		parserdUrl, err := url.Parse(c.TunnelEndpoint)
		if err != nil || parserdUrl.OmitHost || len(parserdUrl.Port()) == 0 || len(parserdUrl.RawPath) != 0 {
			return fmt.Errorf("invalid tunnel-endpoint %s", c.TunnelEndpoint)
		}
	}

	for tunnelName, tunnelConfig := range c.WireguardTunnels {
		profiles := make(map[string]*WireguardTunnelProfileConfiguration, 0)
		for profileName, profile := range tunnelConfig.Profiles {
			ranges := make([]net.IPNet, 0)

			for _, ipRange := range profile.Ranges {
				for _, existingRange := range ranges {
					if existingRange.Contains(ipRange.IP) || ipRange.Contains(existingRange.IP) {
						return fmt.Errorf("network range %v overlaps %v", existingRange, ipRange)
					}
				}
				ranges = append(ranges, ipRange)
			}

			if _, ok := profiles[profileName]; ok {
				return fmt.Errorf("profile %s is duplicated", tunnelName)
			}
			profiles[profileName] = &profile
		}
	}

	return nil
}

type ProvidersConfig struct {
	RouterOS map[string]RouterOSProviderConfig `koanf:"routeros"`
}

type MongoDBConfiguration struct {
	MongoURI  string `koanf:"uri"`
	Database  string `koanf:"database"`
	TimeoutMs uint64 `koanf:"timeoutMs"`
}

func (c MongoDBConfiguration) validate() error {
	if c.MongoURI == "" {
		return errors.New("MongoDB uri must be provided")
	}

	if c.Database == "" {
		return errors.New("MongoDB database must be provided")
	}

	return nil
}

type JWTConfiguration struct {
	JWTSignPrivateKey  string `koanf:"signPrivateKey"`
	JWTValidationKey   string `koanf:"validationKey"`
	JWKSUrl            string `koanf:"jwksUrl"`
	Audience           string `koanf:"audience"`
	Issuer             string `koanf:"issuer"`
	UsernameClaim      string `koanf:"usernameClaim"`
	EmailClaim         string `koanf:"emailClaim"`
	SignExpirationTime uint64 `koanf:"signExpirationTimeMs"`
	KeySignAlgorithm   string `koanf:"keySignAlgorithm"`
}

func (c JWTConfiguration) validate() error {
	if c.UsernameClaim == "" {
		return errors.New("JWT usernameClaim must be provided")
	}

	if (c.JWTValidationKey != "" || c.JWTSignPrivateKey != "") && c.KeySignAlgorithm == "" {
		return errors.New("JWT keySignAlgorithm must be provided if signPrivateKey or validationKey are given")
	} else if c.JWTValidationKey != "" || c.JWTSignPrivateKey != "" {
		switch jwa.KeyAlgorithmFrom(c.KeySignAlgorithm).(type) {
		case jwa.SignatureAlgorithm:
			val := jwa.SignatureAlgorithm(c.KeySignAlgorithm)
			if val != jwa.RS256 && val != jwa.RS384 && val != jwa.RS512 && val != jwa.PS256 && val != jwa.PS384 && val != jwa.PS512 {
				return errors.New("JWT sign algorithm supports only RSA256, RSA384, RSA512, PS256, PS384 and PS512")
			}
		case jwa.InvalidKeyAlgorithm:
			return fmt.Errorf("JWT keySignAlgorithm %s value is not supported", c.KeySignAlgorithm)
		default:
			break
		}
	}

	if c.SignExpirationTime == 0 {
		return errors.New("JWT signExpirationTimeMs cannot be zero")
	}

	return nil
}

type SecurityConfiguration struct {
	CustomCAsPath string           `koanf:"customCaCerts"`
	JWT           JWTConfiguration `koanf:"jwt"`
}

type Config struct {
	LDAPConfiguration    LDAPConfiguration     `koanf:"ldap"`
	MongoDBConfiguration MongoDBConfiguration  `koanf:"mongodb"`
	Providers            ProvidersConfig       `koanf:"providers"`
	Security             SecurityConfiguration `koanf:"security"`
	ServicePort          uint16                `koanf:"port"`
	DebugMode            bool                  `koanf:"debug"`
	SyncPeriodMs         uint64                `koanf:"syncPeriodMs"`
}

func (c *Config) validateRouterOSProviderUniquenessConstraints() error {
	tunnels := make(map[string]struct{}, 0)
	for providerName, provider := range c.Providers.RouterOS {
		tunnelIfaces := make(map[string]struct{}, 0)
		for tunnelName, tunnelConfig := range provider.WireguardTunnels {
			if _, found := tunnels[tunnelName]; !found {
				tunnels[tunnelName] = struct{}{}
			} else {
				return fmt.Errorf("tunnel %s already in use for %s provider", tunnelName, providerName)
			}
			if _, found := tunnelIfaces[tunnelConfig.Interface]; !found {
				tunnelIfaces[tunnelConfig.Interface] = struct{}{}
			} else {
				return fmt.Errorf("interface %s already in use for %s provider",
					tunnelConfig.Interface, providerName)
			}
		}
	}
	return nil
}

func (c *Config) validate() error {
	if c.ServicePort == 0 {
		return errors.New("service port cannot be zero")
	}

	if c.SyncPeriodMs == 0 {
		return errors.New("syncPeriodMs cannot be zero")
	}

	// Validate nested structures
	if err := c.MongoDBConfiguration.validate(); err != nil {
		return err
	}

	if err := c.LDAPConfiguration.validate(); err != nil {
		return err
	}

	if err := c.Security.JWT.validate(); err != nil {
		return err
	}

	// Validate every RouterOS provider configuation
	for _, provider := range c.Providers.RouterOS {
		if err := provider.validate(); err != nil {
			return err
		}
	}

	// Validate provider-wide stuff
	// Important: If new providers are added ensure tunnel name remains "unique" across all of them
	return c.validateRouterOSProviderUniquenessConstraints()
}

func New(path string) (*Config, error) {
	config := &Config{}
	conf, err := loadConfig(path, config)
	if err != nil {
		return nil, err
	}
	return conf, conf.validate()
}

func loadConfig(path string, config *Config) (*Config, error) {
	koanfInstance := koanf.New(".")
	err := koanfInstance.Load(confmap.Provider(map[string]interface{}{
		"port":                              8080,
		"syncPeriodMs":                      900000,
		"mongodb.timeoutMs":                 3000,
		"security.jwt.usernameClaim":        "preferred_username",
		"security.jwt.emailClaim":           "email",
		"security.jwt.signExpirationTimeMs": 86400000,
		"security.jwt.keySignAlgorithm":     "RS256",
		"ldap.userAttribute":                "uid",
		"ldap.emailAttribute":               "mail",
		"ldap.userClass":                    "inetOrgPerson",
	}, "."), nil)
	if err != nil {
		return nil, err
	}

	err = koanfInstance.Load(file.Provider(path), yaml.Parser())
	if err != nil {
		return nil, err
	}

	err = koanfInstance.Load(env.Provider("TPS", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "TPS_")), "_", ".", -1)
	}), nil)
	if err != nil {
		return nil, err
	}

	if err := koanfInstance.UnmarshalWithConf("", config, buildKoanfUnmarshallConfig(config)); err != nil {
		return nil, err
	}

	return config, nil
}

func buildKoanfUnmarshallConfig(output interface{}) koanf.UnmarshalConf {
	return koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToIPHookFunc(),
				mapstructure.StringToIPNetHookFunc(),
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.StringToSliceHookFunc(","),
				mapstructure.TextUnmarshallerHookFunc()),
			Metadata:         nil,
			Result:           output,
			WeaklyTypedInput: true,
		},
	}
}
