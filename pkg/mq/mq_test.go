package mq

import (
	"encoding/json"
	"log"
	"testing"
)

type messge struct {
	Name     string
	Requests string
}

func TestMq(t *testing.T) {
	addr := "amqp://admin:123456@127.0.0.1:5678/"
	pb := NewMqProducer("portscan", addr)
	// var s gonmap.Status
	// s = 0x00001
	// singleScanData := flowport.ScanData{Ip: "127.0.0.1", Port: 80, Status: &s, Response: nil, CrawlerData: nil, SslCert: nil}
	singleScanData := messge{"go", "helloworld"}
	body, err := json.Marshal(singleScanData)
	if err != nil {
		log.Fatal("Failed to marshal user data")
	}
	if err != nil {
		panic(err)
	}
	pb.Push(body)
	pb.Close()
}
