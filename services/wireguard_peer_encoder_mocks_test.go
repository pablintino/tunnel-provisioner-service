// Code generated by MockGen. DO NOT EDIT.
// Source: services/wireguard_peer_encoder.go

// Package services_test is a generated GoMock package.
package services_test

import (
	reflect "reflect"
	models "tunnel-provisioner-service/models"

	gomock "github.com/golang/mock/gomock"
)

// MockWireguardQrEncoder is a mock of WireguardQrEncoder interface.
type MockWireguardQrEncoder struct {
	ctrl     *gomock.Controller
	recorder *MockWireguardQrEncoderMockRecorder
}

// MockWireguardQrEncoderMockRecorder is the mock recorder for MockWireguardQrEncoder.
type MockWireguardQrEncoderMockRecorder struct {
	mock *MockWireguardQrEncoder
}

// NewMockWireguardQrEncoder creates a new mock instance.
func NewMockWireguardQrEncoder(ctrl *gomock.Controller) *MockWireguardQrEncoder {
	mock := &MockWireguardQrEncoder{ctrl: ctrl}
	mock.recorder = &MockWireguardQrEncoderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockWireguardQrEncoder) EXPECT() *MockWireguardQrEncoderMockRecorder {
	return m.recorder
}

// Encode mocks base method.
func (m *MockWireguardQrEncoder) Encode(model *models.WireguardPeerModel, tunnelInfo *models.WireguardTunnelInfo, profileInfo *models.WireguardTunnelProfileInfo, size int) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Encode", model, tunnelInfo, profileInfo, size)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Encode indicates an expected call of Encode.
func (mr *MockWireguardQrEncoderMockRecorder) Encode(model, tunnelInfo, profileInfo, size interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Encode", reflect.TypeOf((*MockWireguardQrEncoder)(nil).Encode), model, tunnelInfo, profileInfo, size)
}
