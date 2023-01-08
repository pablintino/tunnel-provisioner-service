package utils

import (
	"github.com/mitchellh/mapstructure"
	"net"
	"reflect"
)

func StringToIPSlashHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(IPSlash{}) {
			return data, nil
		}

		// Convert it by parsing
		ip, net, err := net.ParseCIDR(data.(string))
		if err != nil {
			return nil, err
		}

		ip, mask := AlignNetMask(ip, net.Mask)
		return &IPSlash{
			IP:   ip,
			Mask: mask,
		}, nil
	}
}
