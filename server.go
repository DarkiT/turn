package turn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/darkit/turn/ipdns"
	"github.com/pion/turn/v4"
)

type Server interface {
	Credentials(id string, addr net.IP) (string, string)
	Disallow(username string)
	Authenticate(username, realm string, addr net.Addr) ([]byte, bool)
}

type InternalServer struct {
	lock   sync.RWMutex
	lookup map[string]Entry
	Lookup map[string]Entry
}

type ExternalServer struct {
	secret    []byte
	ttl       time.Duration
	blacklist map[string]time.Time // 存储被禁用的用户ID及禁用时间
	lock      sync.RWMutex         // 保护并发访问blacklist
}

type Entry struct {
	addr     net.IP
	password []byte
}

const Realm = "zishuo.net"

type Generator struct {
	turn.RelayAddressGenerator
	IPProvider ipdns.Provider
}

func (r *Generator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, addr, err := r.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return conn, addr, err
	}
	relayAddr := *addr.(*net.UDPAddr)

	v4, v6, err := r.IPProvider.Get()
	if err != nil {
		return conn, addr, err
	}

	if v6 == nil || (relayAddr.IP.To4() != nil && v4 != nil) {
		relayAddr.IP = v4
	} else {
		relayAddr.IP = v6
	}
	slog.Debug("TURN已分配", "addr", addr.String(), "relayaddr", relayAddr.String())
	return conn, &relayAddr, err
}

// DefaultConfig 返回一个具有合理默认值的TURN服务器配置
// 用户可以在此基础上修改特定的配置项
func DefaultConfig() Config {
	return Config{
		// 基本服务器配置
		TurnAddress:   ":3478",       // 默认端口
		TurnPortRange: "49152:65535", // 默认推荐的TURN端口范围

		// 默认外部端口
		TurnExternalPort: "3478",

		// 默认拒绝的对等方IP范围
		TurnDenyPeers: []string{
			"0.0.0.0/8",      // 保留地址
			"127.0.0.1/8",    // 本地环回地址
			"10.0.0.0/8",     // 私有网络
			"172.16.0.0/12",  // 私有网络
			"192.168.0.0/16", // 私有网络
			"::/128",         // IPv6未指定地址
			"::1/128",        // IPv6本地环回地址
			"fe80::/10",      // IPv6本地链路地址
		},

		// 默认日志配置
		LogFormat: "text",
		LogLevel:  "info",

		// 默认不启用TLS
		TLSEnabled: false,

		// 默认使用内部认证
		TurnExternal: false,
	}
}

// DefaultConfigWithIP 返回一个包含指定外部IP的默认配置
// 这是一个快速启动方法，只需提供你的服务器公网IP即可
func DefaultConfigWithIP(externalIP string) (Config, error) {
	config := DefaultConfig()

	// 设置外部IP
	if externalIP != "" {
		ipProvider, err := ipdns.NewStatic([]string{externalIP})
		if err != nil {
			return config, fmt.Errorf("创建静态IP提供者失败: %w", err)
		}
		config.TurnIPProvider = ipProvider
		config.TurnExternalIP = []string{externalIP}
	}

	// 预处理CIDR
	if err := config.ParseCIDRs(); err != nil {
		return config, fmt.Errorf("解析CIDR失败: %w", err)
	}

	return config, nil
}

func Start(conf Config) (Server, error) {
	if conf.TurnExternal {
		return newExternalServer(conf)
	} else {
		return newInternalServer(conf)
	}
}

func newExternalServer(conf Config) (Server, error) {
	return &ExternalServer{
		secret:    []byte(conf.TurnExternalSecret),
		ttl:       24 * time.Hour,
		blacklist: make(map[string]time.Time), // 初始化黑名单
	}, nil
}

func newInternalServer(conf Config) (Server, error) {
	udpListener, err := net.ListenPacket("udp", conf.TurnAddress)
	if err != nil {
		return nil, fmt.Errorf("udp: 无法在 %s 上监听: %s", conf.TurnAddress, err)
	}
	tcpListener, err := net.Listen("tcp", conf.TurnAddress)
	if err != nil {
		return nil, fmt.Errorf("tcp: 无法在 %s 上监听: %s", conf.TurnAddress, err)
	}

	svr := &InternalServer{lookup: map[string]Entry{}, Lookup: map[string]Entry{}}

	gen := &Generator{
		RelayAddressGenerator: generator(conf),
		IPProvider:            conf.TurnIPProvider,
	}

	var permissions turn.PermissionHandler = func(clientAddr net.Addr, peerIP net.IP) bool {
		for _, cidr := range conf.TurnDenyPeersParsed {
			if cidr.Contains(peerIP) {
				return false
			}
		}

		return true
	}

	_, err = turn.NewServer(turn.ServerConfig{
		Realm:       Realm,
		AuthHandler: svr.authenticate,
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
		return nil, err
	}

	slog.Info("启动 TURN/STUN", "addr", conf.TurnAddress)
	return svr, nil
}

func generator(conf Config) turn.RelayAddressGenerator {
	min, max, useRange := conf.PortRange()
	if useRange {
		slog.Debug("使用端口范围", "min", min, "max", max)
		return &RelayAddressGeneratorPortRange{MinPort: min, MaxPort: max}
	}
	return &RelayAddressGeneratorNone{}
}

func (a *InternalServer) allow(username, password string, addr net.IP) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.lookup[username] = Entry{
		addr:     addr,
		password: turn.GenerateAuthKey(username, Realm, password),
	}
}

func (a *InternalServer) Disallow(username string) {
	a.lock.Lock()
	defer a.lock.Unlock()

	delete(a.lookup, username)
}

func (a *ExternalServer) Disallow(username string) {
	// 提取用户ID部分
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		// 格式不正确，记录并返回
		slog.Debug("TURN禁用失败：无效的用户名格式", "username", username)
		return
	}

	userID := parts[1]

	// 将用户ID添加到黑名单
	a.lock.Lock()
	defer a.lock.Unlock()
	a.blacklist[userID] = time.Now()

	slog.Info("TURN用户已禁用", "userID", userID)
}

func (a *InternalServer) authenticate(username, realm string, addr net.Addr) ([]byte, bool) {
	a.lock.RLock()
	defer a.lock.RUnlock()

	entry, ok := a.lookup[username]

	if !ok {
		slog.Debug("TURN用户名未找到", "addr", addr, "username", username)
		return nil, false
	}

	slog.Debug("TURN已认证", "addr", addr.String(), "realm", realm)
	return entry.password, true
}

func (a *InternalServer) Authenticate(username, realm string, addr net.Addr) ([]byte, bool) {
	return a.authenticate(username, realm, addr)
}

func (a *ExternalServer) Authenticate(username, realm string, addr net.Addr) ([]byte, bool) {
	if username == "" {
		return nil, false
	}

	// 解析用户名，格式为：timestamp:id
	parts := strings.SplitN(username, ":", 2)
	if len(parts) != 2 {
		slog.Debug("TURN认证失败：无效的用户名格式", "addr", addr.String(), "username", username)
		return nil, false
	}

	timestampStr, userID := parts[0], parts[1]
	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		slog.Debug("TURN认证失败：无效的时间戳", "addr", addr.String(), "timestamp", timestampStr)
		return nil, false
	}

	// 检查是否过期
	if time.Now().Unix() > timestamp {
		slog.Debug("TURN认证失败：凭证已过期", "addr", addr.String(), "userID", userID)
		return nil, false
	}

	// 检查用户ID是否在黑名单中
	a.lock.RLock()
	_, blacklisted := a.blacklist[userID]
	a.lock.RUnlock()

	if blacklisted {
		slog.Debug("TURN认证失败：用户已被禁用", "addr", addr.String(), "userID", userID)
		return nil, false
	}

	// 生成密钥
	mac := hmac.New(sha1.New, a.secret)
	_, _ = mac.Write([]byte(username))
	expectedKey := mac.Sum(nil)

	// 返回生成的密钥和验证结果
	slog.Debug("TURN已认证", "addr", addr.String(), "realm", realm, "userID", userID)
	return expectedKey, true
}

func (a *InternalServer) Credentials(id string, addr net.IP) (string, string) {
	password := randString(20)
	a.allow(id, password, addr)
	return id, password
}

func (a *ExternalServer) Credentials(id string, addr net.IP) (string, string) {
	username := fmt.Sprintf("%d:%s", time.Now().Add(a.ttl).Unix(), id)
	mac := hmac.New(sha1.New, a.secret)
	_, _ = mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return username, password
}
