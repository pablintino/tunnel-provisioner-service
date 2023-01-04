package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
)

type LDAPConfiguration struct {
	LdapURL       string  `koanf:"url"`
	BaseDN        string  `koanf:"baseDn"`
	BindUser      string  `koanf:"bindUser"`
	BindPassword  *string `koanf:"bindPassword"`
	UserFilter    *string `koanf:"userFilter"`
	UserClass     string  `koanf:"userClass"`
	UserAttribute string  `koanf:"userAttribute"`
}

type WireguardTunnelProfileConfiguration struct {
	Ranges []string `koanf:"ranges"`
}

type WireguardTunnelConfiguration struct {
	Profiles  map[string]WireguardTunnelProfileConfiguration `koanf:"profiles"`
	Interface string                                         `koanf:"interface"`
}

type RouterOSProviderConfig struct {
	Host             string                                  `koanf:"host"`
	Port             int                                     `koanf:"port"`
	Username         string                                  `koanf:"username"`
	Password         string                                  `koanf:"password"`
	WireguardTunnels map[string]WireguardTunnelConfiguration `koanf:"wg-tunnels"`
}

type ProvidersConfig struct {
	RouterOS map[string]RouterOSProviderConfig `koanf:"routeros"`
}

type MongoDBConfiguration struct {
	MongoURI string `koanf:"uri"`
	Database string `koanf:"database"`
}

type ServiceConfig struct {
	LDAPConfiguration    LDAPConfiguration    `koanf:"ldap"`
	MongoDBConfiguration MongoDBConfiguration `koanf:"mongodb"`
	Providers            ProvidersConfig      `koanf:"providers"`
	ServicePort          uint16               `koanf:"port"`
	DebugMode            bool                 `koanf:"debug"`
}

func (c *ServiceConfig) validateRouterOSWireguardRanges() error {
	tunnels := make(map[string]*WireguardTunnelConfiguration, 0)
	for _, provider := range c.Providers.RouterOS {
		for tunnelName, tunnelConfig := range provider.WireguardTunnels {
			profiles := make(map[string]*WireguardTunnelProfileConfiguration, 0)
			for profileName, profile := range tunnelConfig.Profiles {
				ranges := make([]net.IPNet, 0)

				for _, ipRange := range profile.Ranges {
					_, net, err := net.ParseCIDR(ipRange)
					if err != nil {
						return errors.New(fmt.Sprintf("Network range %s is invalid. %v", ipRange, err))
					}
					for _, existingRange := range ranges {
						if existingRange.Contains(net.IP) || net.Contains(existingRange.IP) {
							return errors.New(fmt.Sprintf("Network range %s overlaps %s", existingRange.String(), net.String()))
						}
					}
					ranges = append(ranges, *net)
				}

				if _, ok := profiles[profileName]; ok {
					return errors.New(fmt.Sprintf("Profile %s is duplicated", tunnelName))
				}
				profiles[profileName] = &profile
			}
			if _, ok := tunnels[tunnelName]; ok {
				return errors.New(fmt.Sprintf("Tunnel %s is duplicated", tunnelName))
			}
			tunnels[tunnelName] = &tunnelConfig
		}
	}
	return nil
}

func (c *ServiceConfig) Validate() error {
	return c.validateRouterOSWireguardRanges()
}

var koanfInstance = koanf.New(".")

func LoadConfig(config *ServiceConfig) error {

	err := koanfInstance.Load(confmap.Provider(map[string]interface{}{
		"port": 8888,
	}, "."), nil)
	if err != nil {
		return err
	}

	err = koanfInstance.Load(file.Provider("test/config.yaml"), yaml.Parser())
	if err != nil {
		return err
	}

	err = koanfInstance.Load(env.Provider("TPS", ".", func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, "TPS_")), "_", ".", -1)
	}), nil)
	if err != nil {
		return err
	}

	return koanfInstance.Unmarshal("", config)
}

func GetDebugMode() bool {
	return strings.ToLower(os.Getenv("TPS_DEBUG")) == "true"
}
