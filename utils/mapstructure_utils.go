package utils

import (
	"net"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func StringToIPnMaskHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(IPnMask{}) {
			return data, nil
		}

		// Convert it by parsing
		ip, network, err := net.ParseCIDR(data.(string))
		if err != nil {
			return nil, err
		}

		return NewIPnMask(ip, network.Mask), nil
	}
}

func CustomNullablePtrHookFunc(nullTags ...string) mapstructure.DecodeHookFunc {
	return func(
		from reflect.Value,
		to reflect.Value) (interface{}, error) {
		if from.Kind() != reflect.String {
			return from.Interface(), nil
		}
		if to.Kind() != reflect.Ptr {
			return from.Interface(), nil
		}

		value := from.String()
		for _, tag := range nullTags {
			if tag == value {
				return reflect.New(to.Type()).Interface(), nil
			}
		}
		return from.Interface(), nil
	}
}
