package turn

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/pion/turn/v4"
)

// StartTLS 启动一个支持TLS的TURN服务器
// 如果配置中启用了TLS，则使用TLS协议启动TCP监听器
func StartTLS(conf Config) (Server, error) {
	if err := (&conf).PrepareForStart(); err != nil {
		return nil, fmt.Errorf("配置预处理失败: %w", err)
	}

	// 如果配置中未启用TLS，则使用标准的Start函数
	if !conf.TLSEnabled {
		return Start(conf)
	}

	// 加载TLS证书
	cert, err := tls.LoadX509KeyPair(conf.TLSCertFile, conf.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("无法加载TLS证书: %w", err)
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 创建TLS监听器
	tcpListener, err := tls.Listen("tcp", conf.TurnAddress, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("无法在%s上启动TLS监听器: %w", conf.TurnAddress, err)
	}

	// 创建UDP监听器（UDP不支持TLS）
	udpListener, err := net.ListenPacket("udp", conf.TurnAddress)
	if err != nil {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("无法在%s上启动UDP监听器: %w", conf.TurnAddress, err)
	}

	// 根据配置选择服务器类型
	core, err := createServerInstance(conf)
	if err != nil {
		_ = tcpListener.Close()
		_ = udpListener.Close()
		return nil, err
	}

	// 创建中继地址生成器和权限处理器
	gen := &Generator{
		RelayAddressGenerator: generator(conf),
		IPProvider:            conf.TurnIPProvider,
	}

	permissions := createPermissionHandler(conf)

	// 创建TURN服务器
	turnSrv, err := newTurnServer(core, tcpListener, udpListener, gen, permissions)
	if err != nil {
		return nil, err
	}

	runtime := newRuntimeServer(core, turnSrv, tcpListener, udpListener)

	slog.Info("启动 TURN/STUN TLS服务器", "addr", conf.TurnAddress)
	return runtime, nil
}

// createPermissionHandler 创建权限处理函数
func createPermissionHandler(conf Config) func(clientAddr net.Addr, peerIP net.IP) bool {
	return func(clientAddr net.Addr, peerIP net.IP) bool {
		for _, cidr := range conf.TurnDenyPeersParsed {
			if cidr.Contains(peerIP) {
				return false
			}
		}
		return true
	}
}

// newTurnServer 创建一个新的TURN服务器实例

func newTurnServer(core serverCore, tcpListener net.Listener, udpListener net.PacketConn,
	gen *Generator, permissions func(clientAddr net.Addr, peerIP net.IP) bool,
) (*turn.Server, error) {
	var authHandler func(username, realm string, addr net.Addr) ([]byte, bool)

	// 类型断言，将Server接口转换为具体类型
	if internalServer, ok := core.(*InternalServer); ok {
		authHandler = internalServer.authenticate
	} else if externalServer, ok := core.(*ExternalServer); ok {
		authHandler = externalServer.Authenticate
	} else {
		authHandler = core.Authenticate
	}

	return createTurnServer(authHandler, tcpListener, udpListener, gen, permissions)
}

// createTurnServer 创建TURN服务器
func createTurnServer(authHandler func(username, realm string, addr net.Addr) ([]byte, bool),
	tcpListener net.Listener, udpListener net.PacketConn,
	gen *Generator, permissions func(clientAddr net.Addr, peerIP net.IP) bool,
) (*turn.Server, error) {
	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm:       Realm,
		AuthHandler: authHandler,
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener:              tcpListener,
				RelayAddressGenerator: gen,
				PermissionHandler:     permissions,
			},
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn:            udpListener,
				RelayAddressGenerator: gen,
				PermissionHandler:     permissions,
			},
		},
	})
	if err != nil {
		if tcpListener != nil {
			_ = tcpListener.Close()
		}
		if udpListener != nil {
			_ = udpListener.Close()
		}
		return nil, err
	}

	return turnServer, nil
}
