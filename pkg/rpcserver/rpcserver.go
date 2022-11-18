package rpcserver

import (
	"net/http"
	"yscan/pkg/flowport"
	"yscan/pkg/wap"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json"
)

type PortScanArgs struct {
	Ip             string
	Port           string
	Threads        int
	Rate           int
	TimeoutSeconds int
	FilterCount    int
}
type WapArgs struct {
	Url string
}
type WapResults struct {
	wap.CrawlerData
}

type PortScanResults struct {
	Data *[]flowport.ScanData
}

func (p *PortScanArgs) defaultArgs() {
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
}

type PortScanService struct{}

func (h *PortScanService) Scan(r *http.Request, args *PortScanArgs, reply *PortScanResults) error {
	args.defaultArgs()
	reply.Data, _ = flowport.PortAnalyzerScan(args.Ip, args.Port, args.Threads, args.Rate, args.TimeoutSeconds, args.FilterCount)
	log.Infof("success:%s", args.Ip)
	return nil
}

func (h *PortScanService) Wap(r *http.Request, args *WapArgs, reply *WapResults) error {
	reply.URL = args.Url
	reply.RequestGet(flowport.Wapp, 15, "")
	log.Infof("success:%s-%s", reply.URL, reply.Title)
	return nil
}

func RunRpcServer(addr string) {
	log.Printf("Starting RPC Server on :%s\n", addr)
	s := rpc.NewServer()
	s.RegisterCodec(json.NewCodec(), "application/json")
	s.RegisterService(new(PortScanService), "")
	http.Handle("/rpc", s)
	http.ListenAndServe(addr, nil)
}
