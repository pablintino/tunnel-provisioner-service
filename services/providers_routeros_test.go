package services_test

import (
	"fmt"
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

type mockedRouterOSRawApiClientCallData struct {
	Reply          *routeros.Reply
	SimulatedError error
	Count          uint32
}

type MockedRouterOSRawApiClient struct {
	responses map[string]map[string]*mockedRouterOSRawApiClientCallData
	testing   *testing.T
}

func (m *MockedRouterOSRawApiClient) RunArgs(args ...string) (*routeros.Reply, error) {

	if len(args) == 0 {
		m.testing.Fatalf("mock run arguments cannnot be empty")
		return nil, nil
	}

	callData := m.getEnsureMockCallData(args...)
	callData.Count++
	if callData.SimulatedError != nil {
		return nil, callData.SimulatedError
	}
	return callData.Reply, nil
}

func (m *MockedRouterOSRawApiClient) EnsureCommandMatch(count uint32, args ...string) {

	if len(args) == 0 {
		m.testing.Fatalf("mock run arguments cannnot be empty")
		return
	}

	callData := m.getEnsureMockCallData(args...)
	assert.Equal(m.testing, count, callData.Count)
}

func (m *MockedRouterOSRawApiClient) getEnsureMockCallData(command ...string) *mockedRouterOSRawApiClientCallData {
	var argString = ""
	if len(command) > 1 {
		argString = m.splitAndOrderArgs(command[1:]...)
	}

	if res, found := m.responses[command[0]][argString]; found {
		return res
	}
	m.testing.Fatalf("ros mock reply for %s command not found", strings.Join(command, ""))
	return nil
}

func (m *MockedRouterOSRawApiClient) Close() {

}

func (m *MockedRouterOSRawApiClient) AddResponse(reply *routeros.Reply, command string, args ...string) {
	if len(command) == 0 {
		m.testing.Fatalf("mock command cannnot be empty")
		return
	}

	commandArgsMap, found := m.responses[command]
	if !found {
		commandArgsMap = make(map[string]*mockedRouterOSRawApiClientCallData)
		m.responses[command] = commandArgsMap
	}

	callbackData := &mockedRouterOSRawApiClientCallData{Reply: reply}
	if len(args) == 0 {
		commandArgsMap[""] = callbackData
	} else {
		commandArgsMap[m.splitAndOrderArgs(args...)] = callbackData
	}
}

func (m *MockedRouterOSRawApiClient) splitAndOrderArgs(args ...string) string {
	splitTupleArgs := make([]string, len(args))
	copy(splitTupleArgs, args)
	sort.Strings(splitTupleArgs)
	return strings.Join(splitTupleArgs, " ")
}

func NewMockedRouterOSRawApiClient(t *testing.T) *MockedRouterOSRawApiClient {
	return &MockedRouterOSRawApiClient{
		responses: make(map[string]map[string]*mockedRouterOSRawApiClientCallData),
		testing:   t,
	}
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

	apiMock := NewMockedRouterOSRawApiClient(t)

	apiMock.AddResponse(
		&routeros.Reply{
			Re: nil,
			Done: &proto.Sentence{
				Word: "!done",
				Tag:  "",
				List: []proto.Pair{{Key: "ret", Value: "*107"}},
				Map:  map[string]string{"ret": "*107"},
			},
		},
		"/interface/wireguard/peers/add",
		"=interface=test-interface",
		"=public-key=test-key",
		"=preshared-key=test-psk",
		"=comment=@@Tunnel Provisioner Managed: test-description",
		"=allowed-address=192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
	)

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

	apiMock := NewMockedRouterOSRawApiClient(t)

	command := []string{
		"/interface/wireguard/peers/set",
		"=.id=*1D",
		"=interface=test-interface",
		"=public-key=test-key",
		"=preshared-key=test-psk",
		"=comment=@@Tunnel Provisioner Managed: test-description",
		"=allowed-address=192.168.177.2/32,192.168.0.0/24,192.168.1.0/24,192.168.2.0/24",
	}

	apiMock.AddResponse(&routeros.Reply{}, command[0], command[1:]...)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	err := rosProvider.UpdatePeer("*1D", "test-key", "test-description", "test-psk", &tunnelInfo, &profileInfo, hostIp)
	assert.Nil(t, err)
	apiMock.EnsureCommandMatch(1, command...)
}

func TestROsProviderGetPeerByPublicKeyBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	apiMock := NewMockedRouterOSRawApiClient(t)

	command := []string{
		"/interface/wireguard/peers/print",
		fmt.Sprintf("?interface=%s", tunnelInfo.Interface.Name),
		"?public-key=test-key",
	}

	apiMock.AddResponse(&routeros.Reply{
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
	}, command[0], command[1:]...)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	peer, err := rosProvider.GetPeerByPublicKey("test-key", &tunnelInfo)
	assert.Nil(t, err)
	assert.NotNil(t, peer)
	apiMock.EnsureCommandMatch(1, command...)

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

	apiMock := NewMockedRouterOSRawApiClient(t)

	printCommand := []string{
		"/interface/wireguard/peers/print",
		"?public-key=test-key",
		"?interface=test-interface",
	}

	apiMock.AddResponse(&routeros.Reply{
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
	}, printCommand[0], printCommand[1:]...)

	deleteCommand := []string{
		"/interface/wireguard/peers/remove",
		"=.id=*1D",
	}
	apiMock.AddResponse(&routeros.Reply{
		Done: &proto.Sentence{
			Word: "!done",
			Tag:  "",
		},
	}, deleteCommand[0], deleteCommand[1:]...)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	err := rosProvider.DeletePeerByPublicKey(&tunnelInfo, "test-key")
	assert.Nil(t, err)

	apiMock.EnsureCommandMatch(1, printCommand...)
	apiMock.EnsureCommandMatch(1, deleteCommand...)
}

func TestROsProviderGetInterfaceIpBasic(t *testing.T) {
	logging.Initialize(false)
	defer logging.Release()

	rosConfig := config.RouterOSProviderConfig{Username: "username", Host: "host", Port: 12345, Password: "password"}
	tunnelInfo := models.WireguardTunnelInfo{Interface: models.WireguardInterfaceModel{Name: "test-interface"}}

	apiMock := NewMockedRouterOSRawApiClient(t)

	command := []string{
		"/ip/address/print",
		fmt.Sprintf("?interface=%s", tunnelInfo.Interface.Name),
	}

	apiMock.AddResponse(&routeros.Reply{
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
	}, command[0], command[1:]...)

	rosProvider := services.NewROSWireguardRouterProvider("test-ros-provider", &rosConfig, func(*config.RouterOSProviderConfig) (services.RouterOSRawApiClient, error) {
		return apiMock, nil
	})

	ip, network, err := rosProvider.GetInterfaceIp("test-interface")
	assert.Nil(t, err)
	assert.NotNil(t, network)
	apiMock.EnsureCommandMatch(1, command...)

	ip.Equal(net.IPv4(192, 168, 177, 1))
	assert.Equal(t, "192.168.177.0/24", network.String())
}
