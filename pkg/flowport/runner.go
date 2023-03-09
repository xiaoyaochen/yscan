package flowport

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
	"yscan/pkg/gomasscan"
	"yscan/pkg/gonmap"
	"yscan/pkg/mq"
	"yscan/pkg/sslcert"
	"yscan/pkg/wap"

	jsoniter "github.com/json-iterator/go"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
)

type Options struct {
	Threads        int
	FilterCount    int
	TimeoutSeconds int
	Rate           int
	Mode           int
	Ip             string
	Ips            string
	File           string
	Technologies   string
	OutJson        string
	Port           string
	Rpcaddr        string
	Wapp           *wap.Wappalyzer
	MqUrl          string
	Mq             mq.Mq
}

type Runner struct {
	Options
}

func (r *Runner) InitRunner() {
	r.Wapp, _ = wap.InitApp(r.Technologies)
	if r.MqUrl != "" {
		r.Mq = mq.NewMqProducer("portscan", r.MqUrl)
	}
	if r.Ip != "" {
		r.Ips = r.Ip
	} else if r.File != "" {
		fileobj, err := os.Open(r.File)
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
			line = strings.Replace(line, "\r", "", -1)
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
		r.Ips = strings.Join(lines, ",")
	}

}

func (r *Runner) PortAnalyzerScan() (*[]ScanData, error) {
	defer func() {
		if r.MqUrl != "" {
			r.Mq.Close()
		}
	}()
	var filterIpList []string
	if r.Port == "" {
		r.Port = NmapTop1000
	}
	hostList, errs := ParseIps(r.Ips)
	for _, err := range errs {
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	}
	//mode == 1 直接无状态扫描
	if r.Mode == 1 {
		//无状态扫描
		scanPort := parsePortList(r.Port)
		allScanData := *r.SynScan(hostList, scanPort)
		r.OutPortScanJson(&allScanData)
		return &allScanData, nil
	} else {
		//mode 不等于1 先做top50 tcp扫描然后无状态扫描再tcp扫描
		scanPort := parsePortList(r.Port)
		if len(scanPort) <= 50 {
			allScanData := *r.TcpScan(hostList, scanPort)
			r.OutPortScanJson(&allScanData)
			return &allScanData, nil
		} else {
			allScanData := *r.TcpScan(hostList, port_top50)
			filterIpList = append(filterIpList, *filterIps(&allScanData, r.FilterCount)...)
			log.Infoln("Filter Waf IP:", filterIpList)
			//无状态扫描
			hostList = *removeIps(hostList, filterIpList)
			allScanData = append(allScanData, *r.SynScan(hostList, parsePortListExclude(r.Port, port_top50))...)
			r.OutPortScanJson(&allScanData)
			return &allScanData, nil
		}

	}
}

func (r *Runner) SynScan(hosts []string, port_list PortList) *[]ScanData {
	sema := make(chan int, r.Threads)
	client, err := gomasscan.NewScanner()
	var ipports []ipPort
	var allScanData []ScanData
	client.SetRate(r.Rate)
	if err != nil {
		panic(err)
	}
	defer client.Done()
	//开放端口处理函数
	client.HandlerOpen = func(ip string, port int) {
		//输出开放端口
		ipport := ipPort{ip, port}
		if !IsContainIpPort(ipports, ipport) {
			ipports = append(ipports, ipport)
		}
	}
	//将IP地址加入筛选范围内
	for _, host := range hosts {
		_ = client.Add(host)
	}
	go func() {
		for _, p := range port_list {
			p := p
			sema <- 1
			go func() {
				defer func() {
					<-sema
				}()
				for _, host := range hosts {
					client.SendSYN(host, p, gomasscan.SYN)
				}
			}()
		}
	}()
	count := len(port_list) * len(hosts)
	bar := progressbar.NewOptions(count, progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("SYNSCAINING"))
	count_last := 0
	for {
		time.Sleep(time.Second)
		count_now := int(client.Count())
		bar.Add(count_now - count_last)
		count_last = count_now
		if count_now == count {
			time.Sleep(time.Second * 10)
			break
		}
	}

	//tcp
	// wapp, _ := wap.InitApp("")
	bar = progressbar.NewOptions(len(ipports), progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("SYN-TCPSCAINING"))
	withTimeout, cancelFunc := context.WithTimeout(context.Background(), time.Second*3600)
	for _, ipport := range ipports {
		sema <- 1
		port := ipport.port
		host := ipport.ip
		go func() {
			defer func() {
				bar.Add(1)
				<-sema
				wg.Done()
			}()
			singleScanData := r.SingleTcpScan(host, port)
			if singleScanData != nil {
				allScanData = append(allScanData, *singleScanData)
			}
		}()
		wg.Add(1)
	}
	go func() { //协程监听以上协程是否完成
		select {
		case <-withTimeout.Done(): //part1
			return //结束监听协程
		default: //part2 等待协程1、协程2执行完毕，执行完毕后就手动取消上下文，停止阻塞
			wg.Wait()
			cancelFunc()
			return //结束监听协程
		}
	}()
	<-withTimeout.Done()
	return &allScanData

}

func (r *Runner) TcpScan(hosts []string, port_list PortList) *[]ScanData {
	var allScanData []ScanData
	sema := make(chan int, r.Threads)
	// wapp, _ := wap.InitApp("")
	count := len(port_list) * len(hosts)
	bar := progressbar.NewOptions(count, progressbar.OptionShowIts(),
		progressbar.OptionShowCount(),
		progressbar.OptionSetDescription("TCPSCAINING"))
	withTimeout, cancelFunc := context.WithTimeout(context.Background(), time.Second*3600)
	for _, port := range port_list {
		for _, host := range hosts {
			sema <- 1
			port := port
			host := host
			// go GoNmapScan(scanner, host, port, time.Second*30, sema)
			go func() {
				defer func() {
					bar.Add(1)
					<-sema
					wg.Done()
				}()
				singleScanData := r.SingleTcpScan(host, port)
				//推送消息队列保存
				if singleScanData != nil {
					allScanData = append(allScanData, *singleScanData)
				}
			}()
			wg.Add(1)
		}
	}
	go func() { //协程监听以上协程是否完成
		select {
		case <-withTimeout.Done(): //part1
			return //结束监听协程
		default: //part2 等待协程1、协程2执行完毕，执行完毕后就手动取消上下文，停止阻塞
			wg.Wait()
			cancelFunc()
			return //结束监听协程
		}
	}()
	<-withTimeout.Done()
	return &allScanData
}

func (r *Runner) SingleTcpScan(host string, port int) *ScanData {
	var scanner = gonmap.New()
	scanner.OpenDeepIdentify()
	status, response := scanner.ScanTimeout(host, port, time.Second*30)
	if response != nil {
		single_scan := ScanData{host, port, &status, response, &wap.CrawlerData{}, nil}
		// 获取web指纹
		if strings.Contains(single_scan.FingerPrint.Service, "https") {
			single_scan.URL = "https://" + host
			if port != 80 && port != 443 {
				single_scan.URL = single_scan.URL + ":" + strconv.Itoa(port)
			}
			single_scan.RequestGet(r.Wapp, 10, "")
		} else if strings.Contains(single_scan.FingerPrint.Service, "http") {
			single_scan.URL = "http://" + host
			if port != 80 && port != 443 {
				single_scan.URL = single_scan.URL + ":" + strconv.Itoa(port)
			}
			single_scan.RequestGet(r.Wapp, 10, "")
		}
		// 获取证书
		if single_scan.TLS {
			single_scan.SslCert = sslcert.GetCert(host, port)
		}

		apps := []string{}
		for _, v := range single_scan.Apps {
			apps = append(apps, v.Name)
		}
		log.Infoln(single_scan.Ip, single_scan.Port, single_scan.FingerPrint.Service,
			single_scan.Status, single_scan.Title, apps)
		//开启消息队列保存
		if r.MqUrl != "" {
			body, err := json.Marshal(single_scan)
			if err != nil {
				log.Warnln("Failed to marshal singleScanData data")
			}
			err = r.Mq.Push(body)
			if err != nil {
				log.Errorln(err)
			}
		}
		return &single_scan
	} else {
		if status == gonmap.Open || status == gonmap.NotMatched {
			single_scan := ScanData{host, port, &status, response, &wap.CrawlerData{}, nil}
			single_scan.URL = "http://" + host
			if port != 80 && port != 443 {
				single_scan.URL = single_scan.URL + ":" + strconv.Itoa(port)
			}
			single_scan.RequestGet(r.Wapp, 10, "")
			// 获取证书
			if single_scan.TLS {
				single_scan.SslCert = sslcert.GetCert(host, port)
			}

			apps := []string{}
			for _, v := range single_scan.Apps {
				apps = append(apps, v.Name)
			}
			log.Infoln(single_scan.Ip, single_scan.Port, single_scan.FingerPrint.Service,
				single_scan.Status, single_scan.Title, apps)
			//开启消息队列保存
			if r.MqUrl != "" {
				body, err := json.Marshal(single_scan)
				if err != nil {
					log.Warnln("Failed to marshal singleScanData data")
				}
				err = r.Mq.Push(body)
				if err != nil {
					log.Errorln(err)
				}
			}
			return &single_scan
		}
	}
	return nil
}

func (r *Runner) OutPortScanJson(scanResult *[]ScanData) error {
	if r.OutJson != "" {
		out, err := jsoniter.Marshal(&scanResult)
		if err != nil {
			fmt.Println("Json translate fail!")
			return err
		}
		err = ioutil.WriteFile(r.OutJson, out, 0644)
		if err != nil {
			log.Errorf("Json file write error:%v", err)
			return err
		}
	}
	return nil
}
