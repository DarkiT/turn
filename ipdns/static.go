package ipdns

import (
	"fmt"
	"log/slog"
	"net"
)

// Static 静态IP地址提供者
type Static struct {
	v4 net.IP
	v6 net.IP
}

// NewStatic 创建新的静态IP地址提供者
func NewStatic(ips []string) (*Static, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("未提供任何IP地址")
	}

	var v4, v6 net.IP
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("无效的IP地址: %s", ipStr)
		}
		if ip.To4() != nil {
			v4 = ip
		} else {
			v6 = ip
		}
	}

	slog.Info("使用静态外部IP", "v4", v4, "v6", v6)
	return &Static{v4: v4, v6: v6}, nil
}

// Get 获取IPv4和IPv6地址
func (s *Static) Get() (net.IP, net.IP, error) {
	return s.v4, s.v6, nil
}

// NewProber 创建新的IP探测器
func NewProber(stun string, nat1to1 bool) (*Prober, error) {
	return &Prober{
		StunHost: stun,
		NAT1to1:  nat1to1,
	}, nil
}

// Prober IP地址探测器
type Prober struct {
	StunHost string
	NAT1to1  bool
	v4       net.IP
	v6       net.IP
}

// Get 获取IPv4和IPv6地址
func (p *Prober) Get() (net.IP, net.IP, error) {
	// 简单模拟实现，实际应该通过STUN协议获取
	// 此处仅作为接口实现的占位符
	return p.v4, p.v6, nil
}
