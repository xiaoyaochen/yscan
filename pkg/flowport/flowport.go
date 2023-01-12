package flowport

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"
	"yscan/pkg/gomasscan"
	"yscan/pkg/gonmap"
	"yscan/pkg/sslcert"
	"yscan/pkg/wap"

	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
)

var wg sync.WaitGroup
var Wapp *wap.Wappalyzer

type ScanData struct {
	Ip             string `json:"ip"`
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

func PortAnalyzerScan(host string, port string, threads int, rate int, timeoutSeconds int, fcount int, mode int) (*[]ScanData, error) {
	var filterIpList []string
	if port == "" {
		port = NmapTop1000
	}
	hostList, errs := ParseIps(host)
	for _, err := range errs {
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	}
	//mode == 1 直接无状态扫描
	if mode == 1 {
		//无状态扫描
		scanPort := parsePortList(port)
		allScanData := *SynScan(hostList, scanPort, threads, rate)
		return &allScanData, nil
	} else {
		//mode 不等于1 先做top50 tcp扫描然后无状态扫描再tcp扫描
		scanPort := parsePortList(port)
		if len(scanPort) <= 50 {
			allScanData := *TcpScan(hostList, scanPort, threads, timeoutSeconds)
			return &allScanData, nil
		} else {
			allScanData := *TcpScan(hostList, port_top50, threads, timeoutSeconds)
			filterIpList = append(filterIpList, *filterIps(&allScanData, fcount)...)
			log.Infoln("Filter Waf IP:", filterIpList)
			//无状态扫描
			hostList = *removeIps(hostList, filterIpList)
			allScanData = append(allScanData, *SynScan(hostList, parsePortListExclude(port, port_top50), threads, rate)...)
			return &allScanData, nil
		}

	}
}

func SynScan(hosts []string, port_list PortList, threads int, rate int) *[]ScanData {
	sema := make(chan int, threads)
	client, err := gomasscan.NewScanner()
	var ipports []ipPort
	var allScanData []ScanData
	client.SetRate(rate)
	if err != nil {
		panic(err)
	}
	defer client.Done()
	//开放端口处理函数
	client.HandlerOpen = func(ip string, port int) {
		//输出开放端口
		ipport := ipPort{ip, port}
		if !IsContain(ipports, ipport) {
			ipports = append(ipports, ipport)
		}
	}
	//将IP地址加入筛选范围内
	for _, host := range hosts {
		_ = client.Add(host)
	}
	//开始扫描
	// go func() {
	// 	for _, i := range port_list {
	// 		for _, host := range hosts {
	// 			client.SendSYN(host, i, gomasscan.SYN)
	// 		}
	// 	}
	// }()
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
			singleScanData := SingleTcpScan(host, port, time.Second*30, Wapp)
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

func TcpScan(hosts []string, port_list PortList, threads int, timeoutSeconds int) *[]ScanData {
	var allScanData []ScanData
	sema := make(chan int, threads)
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
				singleScanData := SingleTcpScan(host, port, time.Second*time.Duration(timeoutSeconds), Wapp)
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

func SingleTcpScan(host string, port int, timeout time.Duration, wapp *wap.Wappalyzer) *ScanData {
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
			single_scan.RequestGet(wapp, 10, "")
		} else if strings.Contains(single_scan.FingerPrint.Service, "http") {
			single_scan.URL = "http://" + host
			if port != 80 && port != 443 {
				single_scan.URL = single_scan.URL + ":" + strconv.Itoa(port)
			}
			single_scan.RequestGet(wapp, 10, "")
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
		return &single_scan
	} else {
		if status == gonmap.Open || status == gonmap.NotMatched {
			single_scan := ScanData{host, port, &status, response, &wap.CrawlerData{}, nil}
			single_scan.URL = "http://" + host
			if port != 80 && port != 443 {
				single_scan.URL = single_scan.URL + ":" + strconv.Itoa(port)
			}
			single_scan.RequestGet(wapp, 10, "")
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
			return &single_scan
		}
	}
	return nil
}

func IsContain(items []ipPort, item ipPort) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
