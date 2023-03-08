package mq

import (
	"errors"
	"log"
	"os"
	"time"

	"github.com/streadway/amqp"
)

type RbProducer struct {
	name          string
	logger        *log.Logger
	connection    *amqp.Connection
	channel       *amqp.Channel
	done          chan bool
	notifyClose   chan *amqp.Error
	notifyConfirm chan amqp.Confirmation
	isConnected   bool
}

const (
	reconnectDelay = 5 * time.Second // 连接断开后多久重连
	resendDelay    = 5 * time.Second // 消息发送失败后，多久重发
	resendTime     = 3               // 消息重发次数
)

var (
	errNotConnected  = errors.New("not connected to the producer")
	errAlreadyClosed = errors.New("already closed: not connected to the producer")
)

func NewRbProducer(name string, addr string) *RbProducer {
	producer := RbProducer{
		logger: log.New(os.Stdout, "", log.LstdFlags),
		name:   name,
		done:   make(chan bool),
	}
	producer.logger.Println("Attempting to connect")
	for !producer.connect(addr) {
		producer.logger.Println("Failed to connect. Retrying...")
		time.Sleep(reconnectDelay)
	}
	go producer.handleReconnect(addr)
	return &producer
}

// 如果连接失败会不断重连
// 如果连接断开会重新连接
func (producer *RbProducer) handleReconnect(addr string) {
	for {
		select {
		case <-producer.done:
			return
		case <-producer.notifyClose:
			producer.isConnected = false
			producer.logger.Println("Attempting to connect")
			for !producer.connect(addr) {
				producer.logger.Println("Failed to connect. Retrying...")
				time.Sleep(reconnectDelay)
			}
		}
	}
}

// 连接rabbitmq，以生产者的name定义一个队列
func (producer *RbProducer) connect(addr string) bool {
	conn, err := amqp.Dial(addr)
	if err != nil {
		return false
	}
	ch, err := conn.Channel()
	if err != nil {
		return false
	}
	ch.Confirm(false)
	_, err = ch.QueueDeclare(
		producer.name,
		true,  // Durable
		false, // Delete when unused
		false, // Exclusive
		false, // No-wait
		nil,   // Arguments
	)
	if err != nil {
		return false
	}
	producer.changeConnection(conn, ch)
	producer.isConnected = true
	producer.logger.Println("Connected!")
	return true
}

// 监听Rabbit channel的状态
func (producer *RbProducer) changeConnection(connection *amqp.Connection, channel *amqp.Channel) {
	producer.connection = connection
	producer.channel = channel
	// channels没有必要主动关闭。如果没有协程使用它，它会被垃圾收集器收拾
	producer.notifyClose = make(chan *amqp.Error)
	producer.notifyConfirm = make(chan amqp.Confirmation)
	producer.channel.NotifyClose(producer.notifyClose)
	producer.channel.NotifyPublish(producer.notifyConfirm)
}

// 三次重传的发消息
func (producer *RbProducer) Push(data []byte) error {
	if !producer.isConnected {
		return errors.New("failed to push push: not connected")
	}
	var currentTime = 0
	for {
		err := producer.UnsafePush(data)
		if err != nil {
			producer.logger.Println("Push failed. Retrying...")
			currentTime += 1
			if currentTime < resendTime {
				continue
			} else {
				return err
			}
		}
		ticker := time.NewTicker(resendDelay)
		select {
		case confirm := <-producer.notifyConfirm:
			if confirm.Ack {
				producer.logger.Println("Push confirmed!")
				return nil
			}
		case <-ticker.C:
		}
		producer.logger.Println("Push didn't confirm. Retrying...")
	}
}

// 发送出去，不管是否接受的到
func (producer *RbProducer) UnsafePush(data []byte) error {
	if !producer.isConnected {
		return errNotConnected
	}
	return producer.channel.Publish(
		"",            // Exchange
		producer.name, // Routing key
		false,         // Mandatory
		false,         // Immediate
		amqp.Publishing{
			DeliveryMode: 2,
			ContentType:  "application/json",
			Body:         data,
			Timestamp:    time.Now(),
		},
	)
}

// 关闭连接/信道
func (producer *RbProducer) Close() error {
	if !producer.isConnected {
		return errAlreadyClosed
	}
	close(producer.done)
	producer.isConnected = false
	err := producer.channel.Close()
	if err != nil {
		return err
	}
	err = producer.connection.Close()
	if err != nil {
		return err
	}
	return nil
}
