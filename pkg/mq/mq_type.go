package mq

import (
	"yscan/pkg/utils"
)

type Mq interface {
	Push([]byte) error
	Close() error
}

func NewMqProducer(name string, addr string) Mq {
	var pb Mq
	schema := utils.GetSchema(addr)
	switch schema {
	case "redis":
		pb = NewRedisProducer(name, addr)
		return pb
	case "amqp":
		pb = NewRbProducer(name, addr)
		return pb
	default:
		return nil
	}
}
