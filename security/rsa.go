package security

import "encoding/pem"

const (
	rsaPrivateKeyHeader = "RSA PRIVATE KEY"
	rsaPublicKeyHeader  = "RSA PUBLIC KEY"
)

func getPublicKeyFromPEM(pemBytes []byte) *pem.Block {
	data := pemBytes
	for {
		var pemData *pem.Block
		pemData, data = pem.Decode(data)
		if pemData != nil && pemData.Type == rsaPrivateKeyHeader {
			return pemData
		}
		if len(data) == 0 {
			return nil
		}
	}
	return nil
}
