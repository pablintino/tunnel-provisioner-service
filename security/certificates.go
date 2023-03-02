package security

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"tunnel-provisioner-service/logging"
)

type TLSCertificatePool struct {
	RootCAs *x509.CertPool
}

func NewTLSCustomCAs(rootCAsPath string) (*x509.CertPool, error) {
	return loadCACertPool(rootCAsPath)
}

func loadCACertPool(path string) (*x509.CertPool, error) {
	// Important: Use system CAs as base, otherwise the CAs pool will contain only the scanned certificates
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	err = filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			// Is a file, try parse it
			r, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			res := certPool.AppendCertsFromPEM(r)
			if !res {
				logging.Logger.Warnw("Unable to parse certificate in certificate directory as PEM", "file", path)
			} else {
				logging.Logger.Debugw("Successfully added PEM file to Root CAs", "file", path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return certPool, err
}
