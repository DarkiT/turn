package turn

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"errors"
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

type serverCore interface {
	Credentials(id string, addr net.IP) (string, string)
	Disallow(username string)
	Authenticate(username, realm string, addr net.Addr) ([]byte, bool)
}

// Server 表示可控制生命周期的 TURN 服务器
type Server interface {
	serverCore
	Stop(ctx ...context.Context) error
}

var _ Server = (*runtimeServer)(nil)

type runtimeServer struct {
	core        serverCore
	turnServer  *turn.Server
	tcpListener net.Listener
	udpListener net.PacketConn
	stopOnce    sync.Once
	stopErr     error
	stopDone    chan struct{}
}

type InternalServer struct {
	lock   sync.RWMutex
	lookup map[string]Entry
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

func newRuntimeServer(core serverCore, turnSrv *turn.Server, tcpListener net.Listener, udpListener net.PacketConn) *runtimeServer {
	return &runtimeServer{
		core:        core,
		turnServer:  turnSrv,
		tcpListener: tcpListener,
		udpListener: udpListener,
		stopDone:    make(chan struct{}),
	}
}

func (r *runtimeServer) Credentials(id string, addr net.IP) (string, string) {
	return r.core.Credentials(id, addr)
}

func (r *runtimeServer) Disallow(username string) {
	r.core.Disallow(username)
}

func (r *runtimeServer) Authenticate(username, realm string, addr net.Addr) ([]byte, bool) {
	return r.core.Authenticate(username, realm, addr)
}

func (r *runtimeServer) Stop(ctx ...context.Context) error {
	var waitCtx context.Context
	if len(ctx) > 0 && ctx[0] != nil {
		waitCtx = ctx[0]
	} else {
		waitCtx = context.Background()
	}

	r.stopOnce.Do(func() {
		r.stopErr = r.shutdown()
		close(r.stopDone)
	})

	select {
	case <-r.stopDone:
		return r.stopErr
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func (r *runtimeServer) shutdown() error {
	var errs []error

	if r.turnServer != nil {
		if err := r.turnServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if r.tcpListener != nil {
		if err := r.tcpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if r.udpListener != nil {
		if err := r.udpListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

const Realm = "zishuo.net"

type Generator struct {
	turn.RelayAddressGenerator
	IPProvider ipdns.Provider
}

func (r *Generator) AllocatePacketConn(network string, requestedPort int) (net.PacketConn, net.Addr, error) {
	conn, addr, err := r.RelayAddressGenerator.AllocatePacketConn(network, requestedPort)
	if err != nil {
		return nil, nil, err
	}

	if r.IPProvider == nil {
		_ = conn.Close()
		return nil, nil, errors.New("TURN 未配置 IP 提供者")
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("TURN 分配到未知地址类型 %T", addr)
	}

	v4, v6, err := r.IPProvider.Get()
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	if v4 == nil && v6 == nil {
		_ = conn.Close()
		return nil, nil, errors.New("TURN 无法获取任何外部 IP 地址")
	}

	relayAddr := *udpAddr
	if v6 != nil && relayAddr.IP.To4() == nil {
		relayAddr.IP = v6
	} else if v4 != nil {
		relayAddr.IP = v4
	} else {
		relayAddr.IP = v6
	}
	slog.Debug("TURN已分配", "addr", udpAddr.String(), "relayaddr", relayAddr.String())
	return conn, &relayAddr, nil
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

	// 预处理配置
	if err := config.PrepareForStart(); err != nil {
		return config, fmt.Errorf("配置预处理失败: %w", err)
	}

	return config, nil
}

// DefaultConfigWithAuth 返回一个包含外部认证的默认配置
func DefaultConfigWithAuth(externalIP, secret string) (Config, error) {
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

	// 设置外部认证
	if secret != "" {
		config.TurnExternalSecret = secret
	}

	// 预处理配置
	if err := config.PrepareForStart(); err != nil {
		return config, fmt.Errorf("配置预处理失败: %w", err)
	}

	return config, nil
}

// Start 根据配置启动一个 TURN/STUN 服务器
func Start(conf Config) (Server, error) {
	if err := (&conf).PrepareForStart(); err != nil {
		return nil, fmt.Errorf("配置预处理失败: %w", err)
	}

	tcpListener, err := net.Listen("tcp", conf.TurnAddress)
	if err != nil {
		return nil, fmt.Errorf("tcp: 无法在 %s 上监听: %w", conf.TurnAddress, err)
	}

	udpListener, err := net.ListenPacket("udp", conf.TurnAddress)
	if err != nil {
		_ = tcpListener.Close()
		return nil, fmt.Errorf("udp: 无法在 %s 上监听: %w", conf.TurnAddress, err)
	}

	core, err := createServerInstance(conf)
	if err != nil {
		_ = tcpListener.Close()
		_ = udpListener.Close()
		return nil, err
	}

	gen := &Generator{
		RelayAddressGenerator: generator(conf),
		IPProvider:            conf.TurnIPProvider,
	}
	permissions := createPermissionHandler(conf)

	turnSrv, err := newTurnServer(core, tcpListener, udpListener, gen, permissions)
	if err != nil {
		return nil, err
	}

	runtime := newRuntimeServer(core, turnSrv, tcpListener, udpListener)

	slog.Info("启动 TURN/STUN", "addr", conf.TurnAddress)
	return runtime, nil
}

func newExternalServer(conf Config) (serverCore, error) {
	return &ExternalServer{
		secret:    []byte(conf.TurnExternalSecret),
		ttl:       24 * time.Hour,
		blacklist: make(map[string]time.Time), // 初始化黑名单
	}, nil
}

func createServerInstance(conf Config) (serverCore, error) {
	if conf.TurnExternal {
		return newExternalServer(conf)
	}
	return &InternalServer{lookup: map[string]Entry{}}, nil
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
	userID := username
	if strings.Contains(username, ":") {
		parts := strings.SplitN(username, ":", 2)
		if len(parts) == 2 {
			userID = parts[1]
		}
	}
	if userID == "" {
		slog.Debug("TURN禁用失败：无效的用户名格式", "username", username)
		return
	}

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
