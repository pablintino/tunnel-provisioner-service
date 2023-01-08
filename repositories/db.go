package repositories

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsoncodec"
	"go.mongodb.org/mongo-driver/bson/bsonrw"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net"
	"reflect"
	"tunnel-provisioner-service/config"
	"tunnel-provisioner-service/logging"
)

var tIpNet = reflect.TypeOf(net.IPNet{})
var tIp = reflect.TypeOf(net.IP{})

func netIpNetEncodeValue(_ bsoncodec.EncodeContext, vw bsonrw.ValueWriter, val reflect.Value) error {
	if !val.IsValid() || val.Type() != tIpNet {
		return bsoncodec.ValueEncoderError{Name: "ipNetEncodeValue", Types: []reflect.Type{tIpNet}, Received: val}
	}

	strRep := val.Interface().(net.IPNet)
	return vw.WriteString(strRep.String())
}

func netIpEncodeValue(_ bsoncodec.EncodeContext, vw bsonrw.ValueWriter, val reflect.Value) error {
	if !val.IsValid() || val.Type() != tIp {
		return bsoncodec.ValueEncoderError{Name: "netIpEncodeValue", Types: []reflect.Type{tIp}, Received: val}
	}
	s := val.Interface().(net.IP).String()
	return vw.WriteString(s)
}

func netIpNetDecodeValue(_ bsoncodec.DecodeContext, vr bsonrw.ValueReader, val reflect.Value) error {
	if !val.CanSet() || val.Type() != tIpNet {
		return bsoncodec.ValueDecoderError{Name: "netIpNetDecodeValue", Types: []reflect.Type{tIpNet}, Received: val}
	}

	var network *net.IPNet
	var err error
	switch vrType := vr.Type(); vrType {
	case bsontype.String:
		netStr, err := vr.ReadString()
		if err != nil {
			return err
		}
		_, network, err = net.ParseCIDR(netStr)
	case bsontype.Null:
		return vr.ReadNull()
	case bsontype.Undefined:
		return vr.ReadUndefined()
	default:
		return fmt.Errorf("cannot decode %v into a net.IPNet", vr.Type())
	}
	if err != nil {
		return err
	}

	val.Set(reflect.ValueOf(*network))
	return nil
}

func netIpDecodeValue(_ bsoncodec.DecodeContext, vr bsonrw.ValueReader, val reflect.Value) error {
	if !val.CanSet() || val.Type() != tIp {
		return bsoncodec.ValueDecoderError{Name: "netIpDecodeValue", Types: []reflect.Type{tIp}, Received: val}
	}

	var address net.IP
	var err error
	switch vrType := vr.Type(); vrType {
	case bsontype.String:
		ipStr, err := vr.ReadString()
		if err != nil {
			return err
		}
		address = net.ParseIP(ipStr)
	case bsontype.Null:
		return vr.ReadNull()
	case bsontype.Undefined:
		return vr.ReadUndefined()
	default:
		return fmt.Errorf("cannot decode %v into a net.IP", vr.Type())
	}
	if err != nil {
		return err
	}

	val.Set(reflect.ValueOf(address))
	return nil
}

func createCustomRegistry() *bsoncodec.RegistryBuilder {
	var primitiveCodecs bson.PrimitiveCodecs
	rb := bsoncodec.NewRegistryBuilder()
	bsoncodec.DefaultValueEncoders{}.RegisterDefaultEncoders(rb)
	bsoncodec.DefaultValueDecoders{}.RegisterDefaultDecoders(rb)
	rb.RegisterTypeEncoder(tIpNet, bsoncodec.ValueEncoderFunc(netIpNetEncodeValue))
	rb.RegisterTypeEncoder(tIp, bsoncodec.ValueEncoderFunc(netIpEncodeValue))
	rb.RegisterTypeDecoder(tIpNet, bsoncodec.ValueDecoderFunc(netIpNetDecodeValue))
	rb.RegisterTypeDecoder(tIp, bsoncodec.ValueDecoderFunc(netIpDecodeValue))

	primitiveCodecs.RegisterPrimitiveCodecs(rb)
	return rb
}

func BuildClient(mongoConfig config.MongoDBConfiguration) (*mongo.Client, error) {
	// Connect to MongoDB
	mongoconn := options.Client().ApplyURI(mongoConfig.MongoURI).SetRegistry(createCustomRegistry().Build())
	mongoclient, err := mongo.Connect(context.TODO(), mongoconn)
	if err != nil {
		logging.Logger.Errorw("Error configuring/connecting to MongoDB", "error", err)
	}
	return mongoclient, err
}
