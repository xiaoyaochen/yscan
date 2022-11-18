package rpcserver

import (
	"net/http"
	"yscan/pkg/flowport"

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
	reply.Data, _ = flowport.PortAnalyzerScan(args.Ip, args.Port, args.Threads, args.Rate, args.TimeoutSeconds, args.FilterCount, "")
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
