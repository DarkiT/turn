package ipdns

import "net"

// Provider 定义IP地址提供者接口
type Provider interface {
	// Get 获取IPv4和IPv6地址
	Get() (net.IP, net.IP, error)
}
