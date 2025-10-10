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
	stringMin := strings.TrimSpace(parts[0])
	stringMax := strings.TrimSpace(parts[1])
	min64, err := strconv.ParseUint(stringMin, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("无效的最小端口: %s", err)
	}
	max64, err := strconv.ParseUint(stringMax, 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("无效的最大端口: %s", err)
	}
	if min64 == 0 || max64 == 0 {
		return 0, 0, errors.New("端口范围不能包含 0")
	}
	if min64 > max64 {
		return 0, 0, errors.New("端口范围必须满足最小端口小于或等于最大端口")
	}

	return uint16(min64), uint16(max64), nil
}

// ShouldUseTLS 判断是否应该使用TLS
func (c Config) ShouldUseTLS() bool {
	return c.TLSEnabled
}

// ShouldUseExternalAuth 判断是否应该使用外部认证
func (c Config) ShouldUseExternalAuth() bool {
	return c.TurnExternalSecret != ""
}

// Validate 验证配置的有效性
func (c *Config) Validate() error {
	if c.TLSEnabled {
		if c.TLSCertFile == "" {
			return errors.New("启用TLS时必须提供证书文件路径")
		}
		if c.TLSKeyFile == "" {
			return errors.New("启用TLS时必须提供私钥文件路径")
		}
	}

	if c.ShouldUseExternalAuth() {
		if len(c.TurnExternalSecret) < 16 {
			return errors.New("外部认证密钥长度至少为16个字符")
		}
	}

	if c.TurnAddress == "" {
		return errors.New("必须提供监听地址")
	}

	if _, _, err := c.parsePortRange(); err != nil {
		return err
	}

	if c.TurnIPProvider == nil {
		return errors.New("必须提供IP地址提供者或外部IP地址列表")
	}

	return nil
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

// PrepareForStart 准备配置用于启动服务器
func (c *Config) PrepareForStart() error {
	// 设置外部认证标志
	c.TurnExternal = c.ShouldUseExternalAuth()

	if c.TurnIPProvider == nil && len(c.TurnExternalIP) > 0 {
		provider, err := ipdns.NewStatic(c.TurnExternalIP)
		if err != nil {
			return fmt.Errorf("配置验证失败: %w", err)
		}
		c.TurnIPProvider = provider
	}

	// 验证配置
	if err := c.Validate(); err != nil {
		return fmt.Errorf("配置验证失败: %w", err)
	}

	if c.TurnIPProvider == nil {
		return errors.New("配置验证失败: IP 地址提供者未正确配置")
	}

	// 解析CIDR
	if err := c.ParseCIDRs(); err != nil {
		return fmt.Errorf("CIDR解析失败: %w", err)
	}

	return nil
}

// ConfigChain 提供链式配置API
type ConfigChain struct {
	config Config
	err    error
}

// NewConfigChain 创建配置链
func NewConfigChain() *ConfigChain {
	return &ConfigChain{config: DefaultConfig()}
}

// FromConfig 从现有配置创建配置链
func FromConfig(config Config) *ConfigChain {
	return &ConfigChain{config: config}
}

// Address 设置监听地址
func (c *ConfigChain) Address(address string) *ConfigChain {
	if c.err == nil {
		c.config.TurnAddress = address
	}
	return c
}

// PortRange 设置端口范围
func (c *ConfigChain) PortRange(portRange string) *ConfigChain {
	if c.err == nil {
		c.config.TurnPortRange = portRange
	}
	return c
}

// ExternalIP 设置外部IP
func (c *ConfigChain) ExternalIP(ip string) *ConfigChain {
	if c.err != nil {
		return c
	}

	ipProvider, err := ipdns.NewStatic([]string{ip})
	if err != nil {
		c.err = fmt.Errorf("创建IP提供者失败: %w", err)
		return c
	}

	c.config.TurnIPProvider = ipProvider
	c.config.TurnExternalIP = []string{ip}
	return c
}

// ExternalSecret 设置外部认证密钥
func (c *ConfigChain) ExternalSecret(secret string) *ConfigChain {
	if c.err == nil {
		c.config.TurnExternalSecret = secret
	}
	return c
}

// TLS 启用TLS
func (c *ConfigChain) TLS(certFile, keyFile string) *ConfigChain {
	if c.err == nil {
		c.config.TLSEnabled = true
		c.config.TLSCertFile = certFile
		c.config.TLSKeyFile = keyFile
	}
	return c
}

// Logging 设置日志
func (c *ConfigChain) Logging(format, level string) *ConfigChain {
	if c.err == nil {
		c.config.LogFormat = format
		c.config.LogLevel = level
	}
	return c
}

// DenyPeers 设置拒绝的对等方
func (c *ConfigChain) DenyPeers(peers []string) *ConfigChain {
	if c.err == nil {
		c.config.TurnDenyPeers = peers
	}
	return c
}

// Build 构建配置
func (c *ConfigChain) Build() *ConfigResult {
	if c.err != nil {
		return ConfigErr(c.err)
	}

	if err := c.config.PrepareForStart(); err != nil {
		return ConfigErr(err)
	}

	return ConfigOk(c.config)
}

// Start 直接启动服务器
func (c *ConfigChain) Start() *ServerResult {
	configResult := c.Build()
	if configResult.IsErr() {
		return ServerErr(configResult.err)
	}

	server, err := Start(configResult.value)
	return NewResult(server, err)
}

// StartTLS 直接启动TLS服务器
func (c *ConfigChain) StartTLS() *ServerResult {
	configResult := c.Build()
	if configResult.IsErr() {
		return ServerErr(configResult.err)
	}

	server, err := StartTLS(configResult.value)
	return NewResult(server, err)
}
