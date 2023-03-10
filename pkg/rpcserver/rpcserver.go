package rpcserver

import (
	"net/http"
	"yscan/pkg/flowport"
	"yscan/pkg/mq"
	"yscan/pkg/wap"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json"
)

type PortScanArgs struct {
	*flowport.Runner
	// Ip             string
	// Port           string
	// Threads        int
	// Rate           int
	// TimeoutSeconds int
	// FilterCount    int
	// Mode           int
}
type WapArgs struct {
	Url string
}
type WapResults struct {
	wap.CrawlerData
}

type PortScanResults struct {
	Data *[]flowport.ScanData `json:"data"`
}

func (p *PortScanArgs) InitRunner() {
	p.Wapp = Wapp
	p.Ips = p.Ip
	if p.Threads == 0 {
		p.Threads = 100
	}
	if p.Rate == 0 {
		p.Rate = 1000
	}
	if p.TimeoutSeconds == 0 {
		p.TimeoutSeconds = 30
	}
	if p.FilterCount == 0 {
		p.FilterCount = 15
	}
	if p.MqUrl != "" {
		p.Mq = mq.NewMqProducer("portscan", p.MqUrl)
	}
}

type PortScanService struct{}

var Wapp *wap.Wappalyzer

func (h *PortScanService) Scan(r *http.Request, args *PortScanArgs, reply *PortScanResults) error {
	args.InitRunner()
	reply.Data, _ = args.PortAnalyzerScan()
	log.Infof("success:%s", args.Ip)
	return nil
}

func (h *PortScanService) Wap(r *http.Request, args *WapArgs, reply *WapResults) error {
	reply.URL = args.Url
	reply.RequestGet(Wapp, 15, "")
	log.Infof("success:%s-%s", reply.URL, reply.Title)
	return nil
}

func RunRpcServer(runner *flowport.Runner) {
	Wapp = runner.Wapp
	log.Printf("Starting RPC Server on :%s\n", runner.Rpcaddr)
	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")
	s.RegisterService(new(PortScanService), "")
	http.Handle("/rpc", s)
	http.ListenAndServe(runner.Rpcaddr, nil)
}
