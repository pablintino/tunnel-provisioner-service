package security

import "encoding/pem"

const (
	pemBlockTypeRsaPrivateKeyHeader = "RSA PRIVATE KEY"
	pemBlockTypeRsaPublicKeyHeader  = "RSA PUBLIC KEY"
)

type pemBlockType string

func getPemContentBlock(pemBytes []byte, blockType pemBlockType) *pem.Block {
	data := pemBytes
	for {
		var pemData *pem.Block
		pemData, data = pem.Decode(data)
		if pemData != nil && pemData.Type == string(blockType) {
			return pemData
		}
		if len(data) == 0 {
			return nil
		}
	}
	return nil
}
