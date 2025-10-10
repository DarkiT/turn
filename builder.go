package turn

import (
	"fmt"

	"github.com/darkit/turn/ipdns"
)

// ServerBuilder 提供构建器模式来优雅地构建TURN服务器
type ServerBuilder struct {
	config Config
	err    error
}

// NewServerBuilder 创建一个新的服务器构建器
func NewServerBuilder() *ServerBuilder {
	return &ServerBuilder{
		config: DefaultConfig(),
	}
}

// WithAddress 设置监听地址
func (b *ServerBuilder) WithAddress(address string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TurnAddress = address
	return b
}

// WithPortRange 设置端口范围
func (b *ServerBuilder) WithPortRange(portRange string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TurnPortRange = portRange
	return b
}

// WithExternalIP 设置外部IP地址
func (b *ServerBuilder) WithExternalIP(ip string) *ServerBuilder {
	if b.err != nil {
		return b
	}

	ipProvider, err := ipdns.NewStatic([]string{ip})
	if err != nil {
		b.err = fmt.Errorf("创建IP提供者失败: %w", err)
		return b
	}

	b.config.TurnIPProvider = ipProvider
	b.config.TurnExternalIP = []string{ip}
	return b
}

// WithExternalIPs 设置多个外部IP地址
func (b *ServerBuilder) WithExternalIPs(ips []string) *ServerBuilder {
	if b.err != nil {
		return b
	}

	ipProvider, err := ipdns.NewStatic(ips)
	if err != nil {
		b.err = fmt.Errorf("创建IP提供者失败: %w", err)
		return b
	}

	b.config.TurnIPProvider = ipProvider
	b.config.TurnExternalIP = ips
	return b
}

// WithIPProvider 设置自定义IP提供者
func (b *ServerBuilder) WithIPProvider(provider ipdns.Provider) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TurnIPProvider = provider
	return b
}

// WithSTUNProbe 使用STUN探测获取外部IP
func (b *ServerBuilder) WithSTUNProbe(stunServer string) *ServerBuilder {
	if b.err != nil {
		return b
	}

	provider, err := ipdns.NewProber(stunServer, true)
	if err != nil {
		b.err = fmt.Errorf("创建STUN探测器失败: %w", err)
		return b
	}

	b.config.TurnIPProvider = provider
	return b
}

// WithExternalAuth 启用外部认证
func (b *ServerBuilder) WithExternalAuth(secret string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TurnExternalSecret = secret
	return b
}

// WithTLS 启用TLS支持
func (b *ServerBuilder) WithTLS(certFile, keyFile string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TLSEnabled = true
	b.config.TLSCertFile = certFile
	b.config.TLSKeyFile = keyFile
	return b
}

// WithLogging 设置日志配置
func (b *ServerBuilder) WithLogging(format, level string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.LogFormat = format
	b.config.LogLevel = level
	return b
}

// WithDenyPeers 设置拒绝的对等方IP范围
func (b *ServerBuilder) WithDenyPeers(peers []string) *ServerBuilder {
	if b.err != nil {
		return b
	}
	b.config.TurnDenyPeers = peers
	return b
}

// EnableDebugLogging 启用调试日志
func (b *ServerBuilder) EnableDebugLogging() *ServerBuilder {
	return b.WithLogging("text", "debug")
}

// EnableJSONLogging 启用JSON格式日志
func (b *ServerBuilder) EnableJSONLogging() *ServerBuilder {
	return b.WithLogging("json", "info")
}

// Build 构建并启动服务器
func (b *ServerBuilder) Build() (Server, error) {
	if b.err != nil {
		return nil, b.err
	}

	// 预处理配置
	if err := b.config.PrepareForStart(); err != nil {
		return nil, fmt.Errorf("配置预处理失败: %w", err)
	}

	return Start(b.config)
}

// BuildTLS 构建并启动TLS服务器
func (b *ServerBuilder) BuildTLS() (Server, error) {
	if b.err != nil {
		return nil, b.err
	}

	// 预处理配置
	if err := b.config.PrepareForStart(); err != nil {
		return nil, fmt.Errorf("配置预处理失败: %w", err)
	}

	return StartTLS(b.config)
}

// GetConfig 获取构建的配置（用于高级用途）
func (b *ServerBuilder) GetConfig() (Config, error) {
	if b.err != nil {
		return Config{}, b.err
	}

	// 预处理配置
	if err := b.config.PrepareForStart(); err != nil {
		return Config{}, fmt.Errorf("配置预处理失败: %w", err)
	}

	return b.config, nil
}
