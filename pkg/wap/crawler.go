package wap

import (
	"crypto/tls"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	log "github.com/sirupsen/logrus"
)

type CrawlerData struct {
	URL        string              `json:"url,omitempty"`
	HTML       string              `json:"-"`
	Headers    map[string][]string `json:"-"`
	Scripts    []string            `json:"-"`
	Cookies    map[string]string   `json:"-"`
	Meta       map[string][]string `json:"-"`
	Title      string              `json:"title,omitempty"`
	StatusCode int                 `json:"ststus,omitempty"`
	ResURL     string              `json:"-"`
	Apps       []technology        `json:"apps,omitempty"`
}

func (crawler *CrawlerData) RequestGet(wapp *Wappalyzer, timeoutSeconds int, proxy string) {
	// 生成Request对象
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	t.ResponseHeaderTimeout = 10 * time.Second
	if proxy != "" {
		u, _ := url.Parse(proxy)
		t.Proxy = http.ProxyURL(u)
	}
	client := http.Client{
		Timeout:   time.Duration(timeoutSeconds) * time.Second,
		Transport: t,
	}
	req, err := http.NewRequest("GET", crawler.URL, nil)
	if err != nil {
		log.Errorf("New request Error: %s\n", err)
	}
	// 添加Header,cookie
	cookie := &http.Cookie{
		Name:  "rememberMe",
		Value: "me",
	}
	req.AddCookie(cookie)
	// req.Header.Set("Accept", "*/*;q=0.8")
	// req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", rndua())
	// 发起请求
	resp, err := client.Do(req)
	if err != nil && (strings.Contains(err.Error(), "Client.Timeout exceeded while awaiting headers") || strings.Contains(err.Error(), "TLS handshake timeout")) {
		resp, err = client.Do(req)
	}
	if err != nil && (strings.Contains(err.Error(), "Client.Timeout exceeded while awaiting headers") || strings.Contains(err.Error(), "TLS handshake timeout")) {
		resp, err = client.Do(req)
	}

	if err == nil {
		// 设定关闭响应体
		defer resp.Body.Close()
		// 读取响应体
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Body read error: %s\n", err)
		}
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		crawler.HTML = toUtf8(string(body), contentType)
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(crawler.HTML))
		if err == nil {
			//获取title
			crawler.Title = doc.Find("title").Text()
			crawler.Title = strings.Replace(crawler.Title, "\n", "", -1)
			crawler.Title = strings.Trim(crawler.Title, " ")
			//获取script
			doc.Find("script").Each(func(i int, selection *goquery.Selection) {
				if src, _ := selection.Attr("src"); src != "" {
					crawler.Scripts = append(crawler.Scripts, src)
				}
			})
			//获取meta
			crawler.Meta = make(map[string][]string)
			doc.Find("meta").Each(func(i int, selection *goquery.Selection) {
				name, _ := selection.Attr("name")
				if name == "" {
					name, _ = selection.Attr("property")
				}
				if name != "" {
					if content, _ := selection.Attr("content"); content != "" {
						nameLower := strings.ToLower(name)
						crawler.Meta[nameLower] = append(crawler.Meta[nameLower], content)
					}
				}
			})
		}
		crawler.StatusCode = resp.StatusCode
		crawler.Headers = make(map[string][]string)
		for k, v := range resp.Header {
			lowerCaseKey := strings.ToLower(k)
			crawler.Headers[lowerCaseKey] = v
		}
		crawler.Cookies = make(map[string]string)
		for _, cookie := range crawler.Headers["set-cookie"] {
			keyValues := strings.Split(cookie, ";")
			for _, keyValueString := range keyValues {
				keyValueSlice := strings.Split(keyValueString, "=")
				if len(keyValueSlice) > 1 {
					key, value := keyValueSlice[0], keyValueSlice[1]
					crawler.Cookies[key] = value
				}
			}
		}
		crawler.ResURL = resp.Request.URL.String()
	} else {
		log.Errorf("Requests error: %s\n", err)
	}
	AnalyzePage(crawler, wapp)
}

func rndua() string {
	ua := []string{"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0",
		"Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
		"Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows; Intel Windows) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67"}
	n := rand.Intn(13) + 1
	return ua[n]
}
