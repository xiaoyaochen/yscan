package sslcert

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"math/big"
	"strconv"
	"time"
)

type SimpleSslCert struct {
	Raw                 []byte
	Version             int
	SerialNumber        *big.Int
	Issuer              pkix.Name
	Subject             pkix.Name
	NotBefore, NotAfter time.Time // Validity bounds.
}

func GetCert(host string, port int) *SimpleSslCert {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", host+":"+strconv.Itoa(port), conf)
	if err != nil {
		return nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		simplesslcert := SimpleSslCert{
			cert.Raw,
			cert.Version,
			cert.SerialNumber,
			cert.Issuer,
			cert.Subject,
			cert.NotBefore,
			cert.NotAfter,
		}
		// fmt.Printf("Issuer Name: %s\n", cert.Issuer)
		// fmt.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		// fmt.Printf("Common Name: %s \n", cert.Issuer.CommonName)
		return &simplesslcert
	}
	return nil
}
