package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
	"yscan/pkg/flowport"

	jsoniter "github.com/json-iterator/go"
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
	fmt.Printf(logo)
	startTime := time.Now()
	var scanResult *[]flowport.ScanData
	//获取参数
	var threads, filterCount, timeoutSeconds, rate int
	var ip, file, technologies, outJson, port string
	var help bool
	flag.StringVar(&technologies, "technologies", "", "Path to override default technologies.json file")
	flag.StringVar(&file, "file", "", "Ip file for Scan")
	flag.StringVar(&ip, "ip", "", "Ip for Scan")
	flag.StringVar(&port, "port", "", "Port for Scan,default（top1000）")
	flag.IntVar(&timeoutSeconds, "timeout", 30, "Timeout in seconds for TCP Scan")
	flag.IntVar(&threads, "threads", 100, "Threads for TCP Scan")
	flag.IntVar(&filterCount, "fcount", 15, "Ip top50 tcp scan open > fcount to filter")
	flag.IntVar(&rate, "rate", 1000, "rate for SYN Scan")
	flag.StringVar(&outJson, "json", "", "Out json file")
	flag.BoolVar(&help, "h", false, "Help")
	flag.Parse()
	var Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage : yscan [options] <-ip>")
		flag.PrintDefaults()
	}

	if help {
		Usage()
		os.Exit(1)
	}
	if ip == "" && file == "" {
		fmt.Fprintln(os.Stderr, "You must specify a ips to scan")
		Usage()
		os.Exit(1)
	} else if ip != "" {
		scanResult, _ = flowport.PortAnalyzerScan(ip, port, threads, rate, timeoutSeconds, filterCount, technologies)
	} else {
		fileobj, err := os.Open(file)
		if err != nil {
			fmt.Println("File open err!")
		}
		defer fileobj.Close()
		reader := bufio.NewReader(fileobj)
		var lines []string
		for {
			line, err := reader.ReadString('\n') //注意是字符，换行符。
			line = strings.Replace(line, " ", "", -1)
			// 去除换行符
			line = strings.Replace(line, "\n", "", -1)
			lines = append(lines, line)
			if err == io.EOF {
				log.Infof("Ip file read success!\n")
				break
			}
			if err != nil { //错误处理
				log.Errorf("Ip file read error:%v", err)
				return
			}
		}
		log.Info(lines)
		scanResult, _ = flowport.PortAnalyzerScan(strings.Join(lines, ","), port, threads, rate, timeoutSeconds, filterCount, technologies)
	}

	if outJson != "" {
		out, err := jsoniter.Marshal(scanResult)
		if err != nil {
			fmt.Println("Json translate fail!")
			return
		}
		err = ioutil.WriteFile(outJson, out, 0644)
		if err != nil {
			log.Errorf("Json file write error:%v", err)
		}
	}

	elapsed := time.Since(startTime)
	log.Infoln(elapsed)
}
