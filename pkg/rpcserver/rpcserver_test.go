package rpcserver

import (
	"testing"
	"yscan/pkg/flowport"
)

func TestScanner(t *testing.T) {
	var runner *flowport.Runner
	runner.Rpcaddr = "127.0.0.1:10000"
	runner.InitRunner()
	RunRpcServer(runner)
}
