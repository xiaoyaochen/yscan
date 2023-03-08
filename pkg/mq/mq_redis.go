package mq

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/go-redis/redis/v8"
)

type RedisProducer struct {
	name        string
	logger      *log.Logger
	connection  *redis.Client
	isConnected bool
	rdbCtx      context.Context
}

func NewRedisProducer(name string, addr string) *RedisProducer {
	producer := RedisProducer{
		logger: log.New(os.Stdout, "", log.LstdFlags),
		name:   name,
	}
	log.Println("Attempting to connect")
	producer.connect(addr)
	return &producer
}

// 连接rabbitmq，以生产者的name定义一个队列
func (producer *RedisProducer) connect(addr string) bool {
	producer.rdbCtx = context.Background()
	opt, err := redis.ParseURL(addr)
	if err != nil {
		log.Fatalf("Could not parse redis url: %s\n", err)
	}
	producer.connection = redis.NewClient(opt)
	_, err = producer.connection.Ping(producer.rdbCtx).Result()
	if err != nil {
		log.Println("ping err :", err)
		return false
	}
	// defer producer.connection.Close()
	producer.isConnected = true
	return true
}

// 关闭连接/信道
func (producer *RedisProducer) Close() error {
	if !producer.isConnected {
		return errAlreadyClosed
	}
	err := producer.connection.Close()
	if err != nil {
		return err
	}
	producer.isConnected = false
	return nil
}

func (producer *RedisProducer) Push(data []byte) error {
	if !producer.isConnected {
		return errors.New("failed to push push: not connected")
	}
	err := producer.connection.LPush(producer.rdbCtx, producer.name, data).Err()
	if err != nil {
		log.Println("LPush err :", err)
		return err
	}
	return nil
}
