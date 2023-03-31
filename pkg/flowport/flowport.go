package flowport

import (
	"sync"
	"yscan/pkg/gonmap"
	"yscan/pkg/sslcert"
	"yscan/pkg/wap"
)

var wg sync.WaitGroup
var Wapp *wap.Wappalyzer

type ScanData struct {
	Ip             string `json:"ip"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	*gonmap.Status `json:"status"`
	*gonmap.Response
	*wap.CrawlerData
	// SslCert *x509.Certificate `json:"sslcert,omitempty"`
	SslCert *sslcert.SimpleSslCert `json:"sslcert,omitempty"`
}

type ipPort struct {
	ip   string
	port int
}

func IsContainIpPort(items []ipPort, item ipPort) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
