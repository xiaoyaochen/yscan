# yscan
## 简介
    yscan是一款基于go写的端口扫描工具，masscan+nmap+wappalyzer+证书于一体，适用大网测绘。

## 前提

 - 只支持darwin/linux
 - 需要高权限
 - 需要安装libpcap
 
## 特点
 - 高效

## 默认逻辑
    top50 tcp扫描然后做waf判断，减少端口膨胀带来扫描压力->top1000无状态扫描（-port参数可调端口范围）->开放的端口做tcp扫描扫描

## 编译
    go mod tidy
    go build yscan.go

## 感谢
 - [gonmap](https://github.com/lcvvvv/gonmap)
 - [gomasscan](https://github.com/lcvvvv/gomasscan)
 - [gowap] (https://github.com/unstppbl/gowap)
