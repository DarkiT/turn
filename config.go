package turn

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/darkit/turn/ipdns"
)

// Config 代表TURN服务器配置
type Config struct {
	// TLS证书配置
	TLSEnabled  bool   `split_words:"true"` // 是否启用TLS
	TLSCertFile string `split_words:"true"` // TLS证书文件路径
	TLSKeyFile  string `split_words:"true"` // TLS私钥文件路径

	// TURN服务器配置
	TurnAddress   string `default:":3478" required:"true" split_words:"true"` // TURN服务器监听地址
	TurnPortRange string `split_words:"true"`                                 // TURN端口范围，格式为"min:max"

	// TURN外部IP配置
	TurnExternalIP     []string `split_words:"true"`                // TURN服务器的外部IP地址列表
	TurnExternalPort   string   `default:"3478" split_words:"true"` // TURN服务器的外部端口
	TurnExternalSecret string   `split_words:"true"`                // 用于外部TURN认证的密钥

	// 安全配置
	TurnDenyPeers       []string     `default:"0.0.0.0/8,127.0.0.1/8,::/128,::1/128,fe80::/10" split_words:"true"` // 拒绝的对等方IP范围
	TurnDenyPeersParsed []*net.IPNet `ignored:"true"`                                                              // 解析后的拒绝对等方IP网络

	// 日志配置
	LogFormat string `default:"text" split_words:"true"` // 日志格式：text, json, console
	LogLevel  string `default:"info" split_words:"true"` // 日志级别：debug, info, warn, error

	// 内部使用字段
	TurnExternal   bool           `ignored:"true"` // 是否使用外部TURN服务器
	TurnIPProvider ipdns.Provider `ignored:"true"` // IP地址提供者
}

// PortRange 解析端口范围
func (c Config) PortRange() (uint16, uint16, bool) {
	min, max, _ := c.parsePortRange()
	return min, max, min != 0 && max != 0
}

// parsePortRange 解析端口范围字符串
func (c Config) parsePortRange() (uint16, uint16, error) {
	if c.TurnPortRange == "" {
		return 0, 0, nil
	}

	parts := strings.Split(c.TurnPortRange, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("端口范围必须包含一个冒号，格式为 'min:max'")
	}
	stringMin := parts[0]
	stringMax := parts[1]
	min64, err := strconv.ParseUint(stringMin, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("无效的最小端口: %s", err)
	}
	max64, err := strconv.ParseUint(stringMax, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("无效的最大端口: %s", err)
	}

	return uint16(min64), uint16(max64), nil
}

// ShouldUseTLS 判断是否应该使用TLS
func (c Config) ShouldUseTLS() bool {
	return c.TLSEnabled && c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ParseCIDRs 解析网络CIDR
func (c *Config) ParseCIDRs() error {
	c.TurnDenyPeersParsed = make([]*net.IPNet, 0, len(c.TurnDenyPeers))
	for _, peer := range c.TurnDenyPeers {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(peer))
		if err != nil {
			return fmt.Errorf("无法解析CIDR %s: %w", peer, err)
		}
		c.TurnDenyPeersParsed = append(c.TurnDenyPeersParsed, ipNet)
	}
	return nil
}
