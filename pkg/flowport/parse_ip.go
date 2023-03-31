package flowport

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// 192.168.0.1
// 192.168.0.1/24
// 192.168.0.1-22
// 192.168.0.*
// 192.168.0.1，192.168.2.1/24，192.168.3.1-100，192.168.4.*

type IpList []int

func DealCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	//在循环里创建的所有函数变量共享相同的变量。
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); ip_tools(ip) {
		ips = append(ips, ip.String())
	}
	return ips[1 : len(ips)-1], nil
}

func ip_tools(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func DealAsterisk(s string) ([]string, error) {
	i := strings.Count(s, "*")

	switch i {
	case 1:
		return DealCIDR(strings.Replace(s, "*", "1", -1) + "/24")
	case 2:
		return DealCIDR(strings.Replace(s, "*", "1", -1) + "/16")
	case 3:
		return DealCIDR(strings.Replace(s, "*", "1", -1) + "/8")
	}

	return nil, errors.New("wrong Asterisk")
}

func DealHyphen(s string) ([]string, error) {
	tmp := strings.Split(s, ".")
	//TODO 异常处理
	if len(tmp) == 4 {
		iprange_tmp := strings.Split(tmp[3], "-")
		var ips []string
		tail, _ := strconv.Atoi(iprange_tmp[1])
		for head, _ := strconv.Atoi(iprange_tmp[0]); head <= tail; head++ {
			ips = append(ips, tmp[0]+"."+tmp[1]+"."+tmp[2]+"."+strconv.Itoa(head))
		}
		return ips, nil
	} else {
		return nil, errors.New("wrong Hyphen")
	}

}

func ParseIps(s string) ([]string, map[string]string, []error) {

	IPstrings := strings.Split(strings.Trim(s, ","), ",")
	var ips []string
	var err []error
	domainIpMap := make(map[string]string)

	for i := 0; i < len(IPstrings); i++ {
		match, _ := regexp.MatchString("[a-zA-Z]+", IPstrings[i])
		if match {
			//TODO doamin
			aip := DnsResolutionA(IPstrings[i])
			if aip != "" {
				ips = append(ips, aip)
				domainIpMap[IPstrings[i]] = aip
			}
		} else if strings.Contains(IPstrings[i], "*") {
			//TODO 192.168.0.*
			ips_tmp, err_tmp := DealAsterisk(IPstrings[i])
			err = append(err, err_tmp)
			ips = append(ips, ips_tmp...)
		} else if strings.Contains(IPstrings[i], "/") {
			//TODO 192.168.0.1/24
			ips_tmp, err_tmp := DealCIDR(IPstrings[i])
			err = append(err, err_tmp)
			ips = append(ips, ips_tmp...)

		} else if strings.Contains(IPstrings[i], "-") {
			//TODO 192.668.0.1-255
			ips_tmp, err_tmp := DealHyphen(IPstrings[i])
			err = append(err, err_tmp)
			ips = append(ips, ips_tmp...)
		} else {
			//TODO singel ip
			ips = append(ips, IPstrings[i])
		}
	}
	ips = removeDuplicates((ips))
	return ips, domainIpMap, err
}

func filterIps(scanDatas *[]ScanData, maxCount int) *[]string {
	var filterIp []string
	ipMap := make(map[string]int)
	for _, data := range *scanDatas {
		ip := data.Ip
		ipMap[ip] = ipMap[ip] + 1
	}
	for k, v := range ipMap {
		if v > maxCount {
			filterIp = append(filterIp, k)
		}
	}
	return &filterIp
}

func removeIp(ips []string, ip string) *[]string {
	for index, tmp_ip := range ips {
		if tmp_ip == ip {
			ips = append(ips[:index], ips[index+1:]...)
			return &ips
		}
	}
	return &ips
}

func removeIps(ips []string, rips []string) *[]string {
	for _, ip := range rips {
		ips = *removeIp(ips, ip)
	}
	return &ips
}

func DnsResolutionA(domain string) string {
	// 获取域名解析A记录
	ips, err := net.LookupHost(domain)
	if err != nil {
		log.Errorln("域名解析失败:", err)
		return ""
	}
	for _, ip := range ips {
		if parsedIP := net.ParseIP(ip); parsedIP != nil && parsedIP.To4() != nil {
			return ip // 只输出 IPv4 地址
		}
	}
	return ""
}

func removeDuplicates(ips []string) []string {
	m := make(map[string]bool)
	result := []string{}

	for _, ip := range ips {
		if !m[ip] { // 如果 map 中不存在该元素，则添加到结果数组和 map 中
			result = append(result, ip)
			m[ip] = true
		}
	}
	return result
}
