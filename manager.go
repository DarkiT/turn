package turn

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// ServerManager 提供更高级的服务器管理功能
type ServerManager struct {
	server    Server
	config    Config
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.RWMutex
	users     map[string]UserInfo
	stats     ServerStats
	startTime time.Time
}

// UserInfo 存储用户信息
type UserInfo struct {
	ID         string
	CreatedAt  time.Time
	LastUsed   time.Time
	IPAddress  net.IP
	IsDisabled bool
}

// ServerStats 服务器统计信息
type ServerStats struct {
	TotalUsers    int64
	ActiveUsers   int64
	DisabledUsers int64
	StartTime     time.Time
	Uptime        time.Duration
}

// NewServerManager 创建服务器管理器
func NewServerManager(server Server, config Config) *ServerManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ServerManager{
		server:    server,
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		users:     make(map[string]UserInfo),
		startTime: time.Now(),
		stats: ServerStats{
			StartTime: time.Now(),
		},
	}
}

// CreateUser 创建用户并返回凭证
func (m *ServerManager) CreateUser(userID string, clientIP net.IP) (username, password string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查用户是否已存在
	if info, exists := m.users[userID]; exists {
		if info.IsDisabled {
			return "", "", fmt.Errorf("用户 %s 已被禁用", userID)
		}
		// 更新最后使用时间
		info.LastUsed = time.Now()
		m.users[userID] = info
	} else {
		// 创建新用户
		m.users[userID] = UserInfo{
			ID:        userID,
			CreatedAt: time.Now(),
			LastUsed:  time.Now(),
			IPAddress: clientIP,
		}
		m.stats.TotalUsers++
		m.stats.ActiveUsers++
	}

	// 生成凭证
	username, password = m.server.Credentials(userID, clientIP)

	slog.Info("创建用户凭证",
		"userID", userID,
		"username", username,
		"clientIP", clientIP,
	)

	return username, password, nil
}

// DisableUser 禁用用户
func (m *ServerManager) DisableUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.users[userID]
	if !exists {
		return fmt.Errorf("用户 %s 不存在", userID)
	}

	if info.IsDisabled {
		return fmt.Errorf("用户 %s 已被禁用", userID)
	}

	// 标记为禁用
	info.IsDisabled = true
	m.users[userID] = info

	// 调用底层禁用方法
	m.server.Disallow(userID)

	// 更新统计
	m.stats.ActiveUsers--
	m.stats.DisabledUsers++

	slog.Info("禁用用户", "userID", userID)
	return nil
}

// EnableUser 重新启用用户
func (m *ServerManager) EnableUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	info, exists := m.users[userID]
	if !exists {
		return fmt.Errorf("用户 %s 不存在", userID)
	}

	if !info.IsDisabled {
		return fmt.Errorf("用户 %s 未被禁用", userID)
	}

	// 重新启用
	info.IsDisabled = false
	info.LastUsed = time.Now()
	m.users[userID] = info

	// 更新统计
	m.stats.ActiveUsers++
	m.stats.DisabledUsers--

	slog.Info("启用用户", "userID", userID)
	return nil
}

// GetUser 获取用户信息
func (m *ServerManager) GetUser(userID string) (UserInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, exists := m.users[userID]
	if !exists {
		return UserInfo{}, fmt.Errorf("用户 %s 不存在", userID)
	}

	return info, nil
}

// ListUsers 列出所有用户
func (m *ServerManager) ListUsers() []UserInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]UserInfo, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}

	return users
}

// GetStats 获取服务器统计信息
func (m *ServerManager) GetStats() ServerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.Uptime = time.Since(m.startTime)
	return stats
}

// CleanupInactiveUsers 清理不活跃用户
func (m *ServerManager) CleanupInactiveUsers(inactiveTime time.Duration) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-inactiveTime)
	cleaned := 0

	for userID, info := range m.users {
		if !info.IsDisabled && info.LastUsed.Before(cutoff) {
			// 禁用不活跃用户
			info.IsDisabled = true
			m.users[userID] = info
			m.server.Disallow(userID)

			m.stats.ActiveUsers--
			m.stats.DisabledUsers++
			cleaned++

			slog.Info("清理不活跃用户", "userID", userID, "lastUsed", info.LastUsed)
		}
	}

	return cleaned
}

// StartCleanupRoutine 启动定期清理例程
func (m *ServerManager) StartCleanupRoutine(interval, inactiveTime time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cleaned := m.CleanupInactiveUsers(inactiveTime)
				if cleaned > 0 {
					slog.Info("定期清理完成", "cleaned", cleaned)
				}
			case <-m.ctx.Done():
				return
			}
		}
	}()
}

// Stop 停止服务器管理器
func (m *ServerManager) Stop(ctx ...context.Context) {
	m.cancel()
	if err := m.server.Stop(ctx...); err != nil {
		slog.Error("服务器停止失败", "error", err)
	} else {
		slog.Info("TURN服务器已停止")
	}
	slog.Info("服务器管理器已停止")
}

// GetServer 获取底层服务器实例
func (m *ServerManager) GetServer() Server {
	return m.server
}

// WithManager 为现有服务器添加管理功能
func WithManager(server Server, config Config) *ServerManager {
	return NewServerManager(server, config)
}

// QuickStart 提供最简单的启动方式
func QuickStart(externalIP string, options ...func(*ServerBuilder)) (Server, error) {
	builder := NewServerBuilder().WithExternalIP(externalIP)

	// 应用选项
	for _, option := range options {
		option(builder)
	}

	return builder.Build()
}

// QuickStartWithAuth 快速启动带认证的服务器
func QuickStartWithAuth(externalIP, secret string, options ...func(*ServerBuilder)) (Server, error) {
	builder := NewServerBuilder().
		WithExternalIP(externalIP).
		WithExternalAuth(secret)

	// 应用选项
	for _, option := range options {
		option(builder)
	}

	return builder.Build()
}

// 常用选项函数
func WithTLSOption(certFile, keyFile string) func(*ServerBuilder) {
	return func(b *ServerBuilder) {
		b.WithTLS(certFile, keyFile)
	}
}

func WithPortRangeOption(portRange string) func(*ServerBuilder) {
	return func(b *ServerBuilder) {
		b.WithPortRange(portRange)
	}
}

func WithDebugOption() func(*ServerBuilder) {
	return func(b *ServerBuilder) {
		b.EnableDebugLogging()
	}
}
