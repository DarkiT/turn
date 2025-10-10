package ipdns

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun/v3"
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

	if v4 == nil && v6 == nil {
		return nil, fmt.Errorf("未提供任何可解析的 IP 地址")
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
	target, err := normalizeStunTarget(stun)
	if err != nil {
		return nil, err
	}

	return &Prober{
		StunHost: target,
		NAT1to1:  nat1to1,
		cacheTTL: 30 * time.Second,
		timeout:  2 * time.Second,
	}, nil
}

// Prober IP地址探测器
type Prober struct {
	mu        sync.Mutex
	StunHost  string
	NAT1to1   bool
	v4        net.IP
	v6        net.IP
	cacheTTL  time.Duration
	nextFetch time.Time
	lastErr   error
	timeout   time.Duration
}

// Get 获取IPv4和IPv6地址
func (p *Prober) Get() (net.IP, net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	if now.Before(p.nextFetch) && p.lastErr == nil && (p.v4 != nil || p.v6 != nil) {
		return p.v4, p.v6, nil
	}

	v4, v6, err := p.probe()
	if err != nil {
		p.lastErr = err
		p.nextFetch = now.Add(time.Second)
		if p.v4 != nil || p.v6 != nil {
			return p.v4, p.v6, err
		}
		return nil, nil, err
	}

	if !ipEqual(p.v4, v4) || !ipEqual(p.v6, v6) {
		slog.Info("使用 STUN 探测外部IP", "stun", p.StunHost, "v4", v4, "v6", v6)
	}

	p.v4 = v4
	p.v6 = v6
	p.lastErr = nil
	p.nextFetch = now.Add(p.cacheTTL)

	return p.v4, p.v6, nil
}

func (p *Prober) probe() (net.IP, net.IP, error) {
	client, err := stun.Dial("udp", p.StunHost)
	if err != nil {
		return nil, nil, fmt.Errorf("STUN 连接失败: %w", err)
	}
	defer client.Close()

	if p.timeout > 0 {
		client.SetRTO(p.timeout)
	}

	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	var mapped stun.XORMappedAddress
	var eventErr error

	err = client.Do(request, func(event stun.Event) {
		if event.Error != nil {
			eventErr = event.Error
			return
		}
		eventErr = mapped.GetFrom(event.Message)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("STUN 请求失败: %w", err)
	}
	if eventErr != nil {
		return nil, nil, fmt.Errorf("STUN 响应解析失败: %w", eventErr)
	}
	if mapped.IP == nil {
		return nil, nil, fmt.Errorf("STUN 响应未包含外部 IP")
	}

	if mapped.IP.To4() != nil {
		return mapped.IP, nil, nil
	}
	return nil, mapped.IP, nil
}

func ipEqual(a, b net.IP) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}

func normalizeStunTarget(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("STUN 服务器地址不能为空")
	}

	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "stun:") {
		trimmed = "stun:" + trimmed
	}

	uri, err := stun.ParseURI(trimmed)
	if err != nil {
		return "", fmt.Errorf("无效的 STUN 服务器地址: %w", err)
	}
	if uri.Host == "" {
		return "", fmt.Errorf("无效的 STUN 服务器主机名")
	}

	port := uri.Port
	if port == 0 {
		port = 3478
	}

	return net.JoinHostPort(uri.Host, strconv.Itoa(port)), nil
}
