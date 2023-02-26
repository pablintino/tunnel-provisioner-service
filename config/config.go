package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
)

type LDAPConfiguration struct {
	LdapURL        string  `koanf:"url"`
	BaseDN         string  `koanf:"baseDn"`
	BindUser       string  `koanf:"bindUser"`
	BindPassword   *string `koanf:"bindPassword"`
	UserFilter     *string `koanf:"userFilter"`
	UserClass      string  `koanf:"userClass"`
	UserAttribute  string  `koanf:"userAttribute"`
	EmailAttribute string  `koanf:"emailAttribute"`
	SkipVerify     bool    `koanf:"skipVerify"`
	StartTLS       bool    `koanf:"startTLS"`
}

type WireguardTunnelProfileConfiguration struct {
	Ranges []string `koanf:"ranges"`
}

type WireguardTunnelConfiguration struct {
	Profiles  map[string]WireguardTunnelProfileConfiguration `koanf:"profiles"`
	Interface string                                         `koanf:"interface"`
}

type RouterOSProviderConfig struct {
	Host                    string                                  `koanf:"host"`
	Port                    int                                     `koanf:"port"`
	Username                string                                  `koanf:"username"`
	Password                string                                  `koanf:"password"`
	TunnelEndpoint          string                                  `koanf:"tunnels-endpoint"`
	TunnelEndpointInterface string                                  `koanf:"tunnels-endpoint-interface"`
	WireguardTunnels        map[string]WireguardTunnelConfiguration `koanf:"wg-tunnels"`
}

type ProvidersConfig struct {
	RouterOS map[string]RouterOSProviderConfig `koanf:"routeros"`
}

type MongoDBConfiguration struct {
	MongoURI  string `koanf:"uri"`
	Database  string `koanf:"database"`
	TimeoutMs uint64 `koanf:"timeoutMs"`
}

type TLSConfiguration struct {
	CustomCAsPath string `koanf:"customCaCerts"`
}

type ServiceConfig struct {
	LDAPConfiguration    LDAPConfiguration    `koanf:"ldap"`
	MongoDBConfiguration MongoDBConfiguration `koanf:"mongodb"`
	Providers            ProvidersConfig      `koanf:"providers"`
	TLS                  TLSConfiguration     `koanf:"tls"`
	ServicePort          uint16               `koanf:"port"`
	DebugMode            bool                 `koanf:"debug"`
	SyncPeriodMs         uint64               `koanf:"syncPeriodMs"`
}

func (c *ServiceConfig) validateRouterOSWireguardRanges() error {
	for _, provider := range c.Providers.RouterOS {
		for tunnelName, tunnelConfig := range provider.WireguardTunnels {
			profiles := make(map[string]*WireguardTunnelProfileConfiguration, 0)
			for profileName, profile := range tunnelConfig.Profiles {
				ranges := make([]net.IPNet, 0)

				for _, ipRange := range profile.Ranges {
					_, network, err := net.ParseCIDR(ipRange)
					if err != nil {
						return fmt.Errorf("network range %s is invalid. %v", ipRange, err)
					}
					for _, existingRange := range ranges {
						if existingRange.Contains(network.IP) || network.Contains(existingRange.IP) {
							return fmt.Errorf("network range %v overlaps %v", existingRange, network)
						}
					}
					ranges = append(ranges, *network)
				}

				if _, ok := profiles[profileName]; ok {
					return fmt.Errorf("profile %s is duplicated", tunnelName)
				}
				profiles[profileName] = &profile
			}
		}
	}
	return nil
}

func (c *ServiceConfig) validateRouterOSProviderEndpoints() error {
	for providerName, provider := range c.Providers.RouterOS {
		if len(provider.TunnelEndpoint) != 0 && len(provider.TunnelEndpointInterface) != 0 {
			return fmt.Errorf("one of tunnels-endpoint or tunnels-endpoint-interface can be provided in %s provider",
				providerName)
		}
		if len(provider.TunnelEndpoint) != 0 {
			parserdUrl, err := url.Parse(provider.TunnelEndpoint)
			if err != nil || parserdUrl.OmitHost || len(parserdUrl.Port()) == 0 || len(parserdUrl.RawPath) != 0 {
				return fmt.Errorf("invalid tunnel-endpoint %s in %s provider", provider.TunnelEndpoint,
					providerName)
			}
		}
	}
	return nil
}

func (c *ServiceConfig) validateRouterOSProviderUniquenessConstraints() error {
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

func (c *ServiceConfig) Validate() error {
	// Important: If new providers are added ensure tunnel name remains "unique" across all of them
	err := c.validateRouterOSProviderUniquenessConstraints()
	if err != nil {
		return err
	}
	err = c.validateRouterOSProviderEndpoints()
	if err != nil {
		return err
	}
	return c.validateRouterOSWireguardRanges()
}

func NewServiceConfig(path string) (*ServiceConfig, error) {
	config := &ServiceConfig{}
	return loadConfig(path, config)
}

func loadConfig(path string, config *ServiceConfig) (*ServiceConfig, error) {
	koanfInstance := koanf.New(".")
	err := koanfInstance.Load(confmap.Provider(map[string]interface{}{
		"port":              8080,
		"syncPeriodMs":      15000,
		"mongodb.timeoutMs": 3000,
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

	if err := koanfInstance.Unmarshal("", config); err != nil {
		return nil, err
	}

	return config, nil
}
