package services_test

import (
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"gopkg.in/routeros.v2"
	"gopkg.in/routeros.v2/proto"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
	"tunnel-provisioner-service/models"
	"tunnel-provisioner-service/services"
)

func NewCommandEqMatcher(t *testing.T, args ...string) *commandEqMatcher {
	matcher := &commandEqMatcher{t: t}
	matcher.command = matcher.splitAndOrderArgs(args...)
	return matcher
}

type commandEqMatcher struct {
	command string
	t       *testing.T
}

func (e commandEqMatcher) Matches(x interface{}) bool {
	if x == nil {
		return false
	}

	args, ok := reflect.ValueOf(x).Interface().([]string)

	if !ok {
		return false
	}

	return e.command == e.splitAndOrderArgs(args...)
}

func (e commandEqMatcher) splitAndOrderArgs(args ...string) string {
	splitTupleArgs := make([]string, len(args))
	copy(splitTupleArgs, args)
	sort.Strings(splitTupleArgs)
	return strings.Join(splitTupleArgs, " ")
}

func (e commandEqMatcher) String() string {
	return fmt.Sprintf("EQ Matcher ROS command. %s", e.command)
}

func TestROsProviderCreatePeerBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	hostIp, hostNet, _ := net.ParseCIDR("192.168.177.2/32")
	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	profileInfo := models.WireguardTunnelProfileInfo{Ranges: []net.IPNet{*net1, *net2, *net3}}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/peers/add",
		"=interface=test-interface",
		"=public-key=test-key",
		"=preshared-key=test-psk",
		"=comment=@@Tunnel Provisioner Managed: test-description",
		"=allowed-address=192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
	)).Return(&routeros.Reply{
		Re: nil,
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
			List: []proto.Pair{{Key: "ret", Value: "*107"}},
			Map:  map[string]string{"ret": "*107"},
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	peer, err := rosProvider.CreatePeer("test-key", "test-description", "test-psk", &tunnelInfo, &profileInfo, hostIp)

	assert.NotNil(t, peer)
	assert.Nil(t, err)
	expected := &services.WireguardProviderPeer{
		Disabled:       false,
		Id:             "*107",
		Rx:             0,
		Tx:             0,
		PublicKey:      "test-key",
		Description:    "test-description",
		AllowedAddress: []net.IPNet{*hostNet, *net1, *net2, *net3},
	}

	assert.True(t, reflect.DeepEqual(expected, peer))
}

func TestROsProviderUpdatePeerBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	hostIp, _, _ := net.ParseCIDR("192.168.177.2/32")
	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	profileInfo := models.WireguardTunnelProfileInfo{Ranges: []net.IPNet{*net1, *net2, *net3}}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/peers/set",
		"=.id=*1D",
		"=interface=test-interface",
		"=public-key=test-key",
		"=preshared-key=test-psk",
		"=comment=@@Tunnel Provisioner Managed: test-description",
		"=allowed-address=192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
	)).Return(&routeros.Reply{}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	err := rosProvider.UpdatePeer("*1D", "test-key", "test-description", "test-psk", &tunnelInfo, &profileInfo, hostIp)
	assert.Nil(t, err)
}

func TestROsProviderGetPeerByPublicKeyBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/peers/print",
		fmt.Sprintf("?interface=%s", tunnelInfo.Interface.Name),
		"?public-key=test-key",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":                      "*1D",
					"public-key":               "test-key",
					"endpoint-port":            "0",
					"current-endpoint-address": "",
					"allowed-address":          "192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
					"rx":                       "0",
					"tx":                       "0",
					"disabled":                 "false",
					"comment":                  "@@Tunnel Provisioner Managed: Test description",
					"interface":                "test-interface",
					"endpoint-address":         "",
					"current-endpoint-port":    "0",
					"preshaed-key":             "*****",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	peer, err := rosProvider.GetPeerByPublicKey("test-key", &tunnelInfo)
	assert.Nil(t, err)
	assert.NotNil(t, peer)

	_, hostNet, _ := net.ParseCIDR("192.168.177.2/32")
	_, net1, _ := net.ParseCIDR("192.168.0.0/24")
	_, net2, _ := net.ParseCIDR("192.168.1.0/24")
	_, net3, _ := net.ParseCIDR("192.168.2.0/24")
	expected := &services.WireguardProviderPeer{
		Disabled:       false,
		Id:             "*1D",
		Rx:             0,
		Tx:             0,
		PublicKey:      "test-key",
		Description:    "Test description",
		AllowedAddress: []net.IPNet{*hostNet, *net1, *net2, *net3},
	}

	assert.True(t, reflect.DeepEqual(expected, peer))
}

func TestROsProviderDeletePeerByPublicKeyBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/peers/print",
		"?public-key=test-key", "?interface=test-interface",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":                      "*1D",
					"public-key":               "test-key",
					"endpoint-port":            "0",
					"current-endpoint-address": "",
					"allowed-address":          "192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
					"rx":                       "0",
					"tx":                       "0",
					"disabled":                 "false",
					"comment":                  "@@Tunnel Provisioner Managed: Test description",
					"interface":                "test-interface",
					"endpoint-address":         "",
					"current-endpoint-port":    "0",
					"preshaed-key":             "*****",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/peers/remove",
		"=.id=*1D",
	)).Return(&routeros.Reply{
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	err := rosProvider.DeletePeerByPublicKey(&tunnelInfo, "test-key")
	assert.Nil(t, err)
}

func TestROsProviderGetInterfaceIpBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/ip/address/print",
		fmt.Sprintf("?interface=%s", tunnelInfo.Interface.Name),
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":       "*2",
					"address":   "192.168.177.1/24",
					"network":   "192.168.177.0",
					"interface": "test-wg",
					"invalid":   "false",
					"dynamic":   "false",
					"disabled":  "false",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	ip, network, err := rosProvider.GetInterfaceIp("test-interface")
	assert.Nil(t, err)
	assert.NotNil(t, network)

	ip.Equal(net.IPv4(192, 168, 177, 1))
	assert.Equal(t, "192.168.177.0/24", network.String())
}

func TestROsProviderGetTunnelInterfaceInfoFromCloudBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/ip/cloud/print",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					"ddns-enabled":         "true",
					"ddns-update-interval": "none",
					"update-time":          "false",
					"public-address":       "1.1.1.1",
					"dns-name":             "7328742384nbff4.sn.mynetname.net",
					"status":               "updated",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/print", "?name=test-interface",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":         "*1D",
					"name":        "test-interface",
					"mtu":         "1420",
					"listen-port": "13231",
					"private-key": "*****",
					"public-key":  "test-key",
					"running":     "true",
					"disabled":    "false",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	ifaceInfo, err := rosProvider.GetTunnelInterfaceInfo("test-interface")
	assert.Nil(t, err)
	assert.NotNil(t, ifaceInfo)
	assert.Equal(t, "7328742384nbff4.sn.mynetname.net:13231", ifaceInfo.Endpoint)
	assert.Equal(t, "test-interface", ifaceInfo.Name)
	assert.Equal(t, "test-key", ifaceInfo.PublicKey)
	assert.True(t, ifaceInfo.Enabled)
}

func TestROsProviderGetTunnelInterfaceInfoFromIfaceBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password", TunnelEndpointInterface: "out-iface"}

	ctrl := gomock.NewController(t)
	apiMock := NewMockRouterOSRawApiClient(ctrl)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/ip/address/print", "?interface=out-iface",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":       "*2",
					"address":   "1.1.1.1/32",
					"network":   "1.1.1.0",
					"interface": "test-wg",
					"invalid":   "false",
					"dynamic":   "false",
					"disabled":  "false",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	apiMock.EXPECT().RunArgs(NewCommandEqMatcher(t,
		"/interface/wireguard/print", "?name=test-interface",
	)).Return(&routeros.Reply{
		Re: []*proto.Sentence{
			{
				Word: "!re",
				Tag:  "",
				Map: map[string]string{
					".id":         "*1D",
					"name":        "test-interface",
					"mtu":         "1420",
					"listen-port": "13231",
					"private-key": "*****",
					"public-key":  "test-key",
					"running":     "true",
					"disabled":    "false",
				},
			},
		},
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, nil)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	ifaceInfo, err := rosProvider.GetTunnelInterfaceInfo("test-interface")
	assert.Nil(t, err)
	assert.NotNil(t, ifaceInfo)
	assert.Equal(t, "1.1.1.1:13231", ifaceInfo.Endpoint)
	assert.Equal(t, "test-interface", ifaceInfo.Name)
	assert.Equal(t, "test-key", ifaceInfo.PublicKey)
	assert.True(t, ifaceInfo.Enabled)
}
