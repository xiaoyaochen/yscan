package sslcert

import (
	"fmt"
	"testing"
)

func TestGetssl(t *testing.T) {
	fmt.Println(GetCert("192.168.10.231", 443))
}
