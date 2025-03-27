package ipdns

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"log/slog"
)

// DNS 表示一个DNS提供者，用于通过DNS查找获取IP地址
type DNS struct {
	sync.Mutex

	DNS      string
	Resolver *net.Resolver
	Domain   string

	refetch time.Time
	v4      net.IP
	v6      net.IP
	err     error
}

// Get 获取IPv4和IPv6地址
func (s *DNS) Get() (net.IP, net.IP, error) {
	s.Lock()
	defer s.Unlock()

	if s.refetch.Before(time.Now()) {
		oldV4, oldV6 := s.v4, s.v6
		s.v4, s.v6, s.err = s.lookup()
		if s.err == nil {
			if !oldV4.Equal(s.v4) || !oldV6.Equal(s.v6) {
				slog.Info("DNS External IP",
					"v4", s.v4.String(),
					"v6", s.v6.String(),
					"domain", s.Domain,
					"dns", s.DNS)
			}
			s.refetch = time.Now().Add(time.Minute)
		} else {
			// 避免频繁请求DNS服务器
			s.refetch = time.Now().Add(time.Second)
			slog.Error("DNS External IP",
				"error", s.err,
				"domain", s.Domain,
				"dns", s.DNS)
		}
	}

	return s.v4, s.v6, s.err
}

// lookup 查找DNS记录
func (s *DNS) lookup() (net.IP, net.IP, error) {
	ips, err := s.Resolver.LookupIP(context.Background(), "ip", s.Domain)
	if err != nil {
		if dns, ok := err.(*net.DNSError); ok && s.DNS != "system" {
			dns.Server = ""
		}
		return nil, nil, err
	}

	var v4, v6 net.IP
	for _, ip := range ips {
		isV6 := strings.Contains(ip.String(), ":")
		if isV6 && v6 == nil {
			v6 = ip
		} else if !isV6 && v4 == nil {
			v4 = ip
		}
	}

	if v4 == nil && v6 == nil {
		return nil, nil, errors.New("DNS记录没有A或AAAA记录")
	}

	return v4, v6, nil
}
