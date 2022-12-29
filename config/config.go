package config

import (
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env"
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
	Profiles map[string]WireguardTunnelProfileConfiguration `koanf:"profiles"`
}

type RouterOSProviderConfig struct {
	Host             string                                  `koanf:"host"`
	Port             string                                  `koanf:"port"`
	Username         string                                  `koanf:"username"`
	Password         string                                  `koanf:"password"`
	WireguardTunnels map[string]WireguardTunnelConfiguration `koanf:"wg-tunnels"`
}

type ProvidersConfig struct {
	RouterOS []RouterOSProviderConfig `koanf:"routeros"`
}

type MongoDBConfiguration struct {
	MongoURI string `koanf:"uri"`
	Database string `koanf:"database"`
}

type RouterOSConfig struct {
}

type ServiceConfig struct {
	LDAPConfiguration    LDAPConfiguration    `koanf:"ldap"`
	MongoDBConfiguration MongoDBConfiguration `koanf:"mongodb"`
	Providers            ProvidersConfig      `koanf:"providers"`
	ServicePort          uint16               `koanf:"port"`
	DebugMode            bool                 `koanf:"debug"`
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
