package main

import (
	"flag"
	"fmt"
	"os"
	"time"
	"yscan/pkg/flowport"
	"yscan/pkg/rpcserver"

	log "github.com/sirupsen/logrus"
)

//logo信息
const logo = `
___.__.  ______  ____  _____     ____  
<   |  | /  ___/_/ ___\ \__  \   /    \ 
 \___  | \___ \ \  \___  / __ \_|   |  \
 / ____|/____  > \___  >(____  /|___|  /
 \/ 
`

func main() {
	// fmt.Printf(logo)
	startTime := time.Now()
	//获取参数
	var runner flowport.Runner
	var help bool
	flag.StringVar(&runner.Technologies, "technologies", "", "Path to override default technologies.json file")
	flag.StringVar(&runner.File, "file", "", "Ip file for Scan")
	flag.StringVar(&runner.Rpcaddr, "rpcaddr", "", "rpc listen address")
	flag.StringVar(&runner.Ip, "ip", "", "Ip for Scan , `-` for stdin")
	flag.StringVar(&runner.Port, "port", "", "Port for Scan,default（top1000）")
	flag.IntVar(&runner.TimeoutSeconds, "timeout", 30, "Timeout in seconds for TCP Scan")
	flag.IntVar(&runner.Threads, "threads", 100, "Threads for TCP Scan")
	flag.IntVar(&runner.FilterCount, "fcount", 15, "Ip top50 tcp scan open > fcount to filter")
	flag.IntVar(&runner.Rate, "rate", 1000, "rate for Asyn Scan (masscan SYN scan)")
	flag.IntVar(&runner.Mode, "mode", 0, "0:default scan(top50 tcp->Async->tcp), 1:Async Scan(Async->tcp) 2:(pure tcp scan )")
	flag.StringVar(&runner.OutJson, "json", "", "Out json file")
	flag.StringVar(&runner.MqUrl, "mq", "", "Out to Mq(redis、rabbitmq)")
	flag.BoolVar(&help, "h", false, "Help")
	flag.Parse()
	//初始化参数
	runner.InitRunner()
	//查看帮助
	var Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage : yscan [options] <-ip>")
		flag.PrintDefaults()
	}
	if help {
		Usage()
		os.Exit(1)
	}
	if runner.Ips == "" {
		if runner.Rpcaddr == "" {
			fmt.Fprintln(os.Stderr, "You must specify a ips to scan")
			Usage()
			os.Exit(1)
		} else {
			rpcserver.RunRpcServer(&runner)
		}
	} else {
		_, err := runner.PortAnalyzerScan()
		if err != nil {
			log.Errorln(err)
		}
	}

	elapsed := time.Since(startTime)
	log.Infoln(elapsed)
}
