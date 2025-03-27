# TURN/STUN 服务器

这个包提供了一个完整且灵活的 TURN/STUN 服务器实现，支持 TCP、UDP 和 TLS 传输，适用于 WebRTC 应用程序。

## 功能特性

- 同时支持 TURN 和 STUN 协议
- 支持多种传输协议：UDP、TCP、TLS
- 灵活的认证模式：内部认证和外部认证
- IP 地址管理：静态 IP 和基于 DNS 的自动发现
- 端口范围控制：可自定义端口分配策略
- 安全访问控制：支持 IP 黑名单和用户黑名单
- 标准日志系统：使用 Go 标准库的 `log/slog`
- 多样化日志格式：支持 JSON、文本和控制台输出
- 内置默认配置：快速部署服务器的便捷方法

## 安装

```bash
go get github.com/darkit/turn
```

## 快速开始

### 使用默认配置（最简方式）

```go
package main

import (
    "log/slog"
    "os"
    "github.com/darkit/turn"
)

func main() {
    // 使用默认配置并提供外部IP
    config, err := turn.DefaultConfigWithIP("203.0.113.5")
    if err != nil {
        slog.Error("无法创建默认配置", "error", err)
        os.Exit(1)
    }
    
    // 启动服务器
    server, err := turn.Start(config)
    if err != nil {
        slog.Error("无法启动TURN服务器", "error", err)
        os.Exit(1)
    }
    
    // 服务器已启动，等待中断信号...
}
```

### 自定义基于默认配置

```go
package main

import (
    "log/slog"
    "os"
    "github.com/darkit/turn"
)

func main() {
    // 获取默认配置
    config := turn.DefaultConfig()
    
    // 自定义特定选项
    config.TurnAddress = ":3479"  // 更改监听端口
    config.LogLevel = "debug"     // 更改日志级别
    
    // 创建IP提供者
    ipProvider, err := turn.ipdns.NewStatic([]string{"203.0.113.5"})
    if err != nil {
        slog.Error("无法创建IP地址提供者", "error", err)
        os.Exit(1)
    }
    config.TurnIPProvider = ipProvider
    
    // 解析CIDR
    if err := config.ParseCIDRs(); err != nil {
        slog.Error("无法解析拒绝的对等方IP", "error", err)
        os.Exit(1)
    }
    
    // 启动服务器
    server, err := turn.Start(config)
    if err != nil {
        slog.Error("无法启动TURN服务器", "error", err)
        os.Exit(1)
    }
    
    // 服务器已启动，等待中断信号...
}
```

### 完全自定义配置

```go
package main

import (
    "log/slog"
    "os"
    "github.com/darkit/turn"
    "github.com/darkit/turn/ipdns"
)

func main() {
    // 配置日志
    turn.ConfigureLogger("text", "info")
    
    // 创建一个静态IP提供者
    ipProvider, err := ipdns.NewStatic([]string{"203.0.113.5"})
    if err != nil {
        slog.Error("无法创建IP地址提供者", "error", err)
        os.Exit(1)
    }
    
    // 创建配置
    config := turn.Config{
        TurnAddress:     ":3478",
        TurnIPProvider:  ipProvider,
        TurnDenyPeers:   []string{"0.0.0.0/8", "127.0.0.1/8"},
    }
    
    // 解析CIDR
    if err := config.ParseCIDRs(); err != nil {
        slog.Error("无法解析拒绝的对等方IP", "error", err)
        os.Exit(1)
    }
    
    // 启动服务器
    server, err := turn.Start(config)
    if err != nil {
        slog.Error("无法启动TURN服务器", "error", err)
        os.Exit(1)
    }
    
    // 服务器已启动，等待中断信号...
}
```

### 使用TLS

```go
package main

import (
    "log/slog"
    "os"
    "github.com/darkit/turn"
)

func main() {
    // 获取默认配置并启用TLS
    config := turn.DefaultConfig()
    config.TLSEnabled = true
    config.TLSCertFile = "/path/to/cert.pem"
    config.TLSKeyFile = "/path/to/key.pem"
    
    // 设置外部IP
    ipProvider, err := turn.ipdns.NewStatic([]string{"203.0.113.5"})
    if err != nil {
        slog.Error("无法创建IP地址提供者", "error", err)
        os.Exit(1)
    }
    config.TurnIPProvider = ipProvider
    
    // 解析CIDR
    if err := config.ParseCIDRs(); err != nil {
        slog.Error("无法解析拒绝的对等方IP", "error", err)
        os.Exit(1)
    }
    
    // 启动TLS服务器
    server, err := turn.StartTLS(config)
    if err != nil {
        slog.Error("无法启动TURN TLS服务器", "error", err)
        os.Exit(1)
    }
    
    // 服务器已启动，等待中断信号...
}
```

### 禁用用户

```go
// 获取服务器实例
server, err := turn.Start(config)
if err != nil {
    slog.Error("无法启动TURN服务器", "error", err)
    os.Exit(1)
}

// 为用户生成凭证
username, password := server.Credentials("user123", net.ParseIP("192.168.1.100"))
slog.Info("生成用户凭证", "username", username, "password", password)

// 稍后，如果需要禁用此用户
server.Disallow(username)
slog.Info("用户已被禁用", "username", username)
```

## 命令行工具

包中提供了一个完整的命令行TURN服务器应用程序：

```bash
# 启动基本TLS TURN服务器
go run ./pkg/turn/turn-tls-server/main.go \
  -tls-cert /path/to/cert.pem \
  -tls-key /path/to/key.pem \
  -turn-address :3478 \
  -turn-port-range 49160:49200 \
  -turn-external-ip 203.0.113.5 \
  -log-level debug
```

## 配置详解

### 默认配置函数

包提供了两个便捷的默认配置函数：

```go
// 返回具有合理默认值的基本配置
config := turn.DefaultConfig()

// 快速创建包含外部IP的配置
config, err := turn.DefaultConfigWithIP("203.0.113.5")
```

`DefaultConfig` 提供的默认值包括：
- 监听地址 `:3478`
- 端口范围 `49152:65535`（IANA推荐的临时端口范围）
- 默认的IP黑名单（私有网络、保留地址等）
- 文本格式的INFO级别日志
- 使用内部认证
- 不启用TLS

`DefaultConfigWithIP` 在默认配置基础上添加：
- 配置提供的外部IP
- 自动创建静态IP提供者
- 自动解析CIDR黑名单

### 核心配置选项

`Config` 结构体包含以下重要配置项：

```go
type Config struct {
    // TLS证书配置
    TLSEnabled  bool   // 是否启用TLS
    TLSCertFile string // TLS证书文件路径
    TLSKeyFile  string // TLS私钥文件路径

    // TURN服务器配置
    TurnAddress   string // TURN服务器监听地址，默认":3478"
    TurnPortRange string // TURN端口范围，格式为"min:max"

    // TURN外部IP配置
    TurnExternalIP     []string        // TURN服务器的外部IP地址列表
    TurnExternalPort   string          // TURN服务器的外部端口，默认"3478"
    TurnExternalSecret string          // 用于外部认证的密钥
    TurnIPProvider     ipdns.Provider  // IP地址提供者

    // 安全配置
    TurnDenyPeers       []string     // 拒绝的对等方IP范围
    TurnDenyPeersParsed []*net.IPNet // 解析后的拒绝对等方IP网络

    // 日志配置
    LogFormat string // 日志格式：text, json, console
    LogLevel  string // 日志级别：debug, info, warn, error

    // 内部使用字段
    TurnExternal bool // 是否使用外部TURN服务器
}
```

### IP地址提供者

IP地址提供者用于确定TURN服务器的外部IP地址，有以下几种实现：

1. **静态IP提供者**：明确指定外部IPv4和IPv6地址
   ```go
   provider, err := ipdns.NewStatic([]string{"203.0.113.5", "2001:db8::1"})
   ```

2. **DNS提供者**：通过DNS记录获取IP地址
   ```go
   resolver := &net.Resolver{/* 配置 */}
   provider := &ipdns.DNS{
       DNS:      "1.1.1.1:53",
       Resolver: resolver,
       Domain:   "turn.example.com",
   }
   ```

3. **STUN探测器**：通过STUN服务器探测外部IP（简化实现）
   ```go
   provider, err := ipdns.NewProber("stun.l.google.com:19302", true)
   ```

### 认证模式

TURN服务器支持两种认证模式：

1. **内部认证**：在服务器内部管理凭证
   ```go
   // 不提供TurnExternalSecret，将使用内部认证
   config := turn.Config{
       // ...其他配置
       TurnExternal: false,
   }
   ```

2. **外部认证**：使用外部密钥生成凭证
   ```go
   config := turn.Config{
       // ...其他配置
       TurnExternalSecret: "your-shared-secret",
       TurnExternal: true,
   }
   ```

### 用户管理

#### 内部认证模式

在内部认证模式下，服务器直接存储用户凭证：

```go
// 生成凭证并存储在服务器中
username, password := server.Credentials("user123", clientIP)

// 禁用用户（立即生效）
server.Disallow(username)
```

#### 外部认证模式

在外部认证模式下，服务器使用共享密钥和时间戳生成临时凭证：

```go
// 生成基于时间的临时凭证
username, password := server.Credentials("user123", clientIP)
// 格式为：timestamp:userID

// 禁用用户（通过黑名单机制实现）
server.Disallow(username)
```

外部认证模式下的黑名单机制会提取用户名中的ID部分（而不是时间戳），并将其加入黑名单。这样即使用户尝试使用有效的时间戳重新获取凭证，只要用户ID在黑名单中，认证仍会失败。

### 端口范围控制

可以限制TURN服务器使用的端口范围：

```go
config := turn.Config{
    // ...其他配置
    TurnPortRange: "49160:49200", // 端口范围从49160到49200
}
```

### 安全访问控制

可以通过设置黑名单阻止特定IP范围：

```go
config := turn.Config{
    // ...其他配置
    TurnDenyPeers: []string{
        "0.0.0.0/8",     // 保留地址
        "127.0.0.1/8",   // 本地环回地址
        "10.0.0.0/8",    // 私有网络
        "172.16.0.0/12", // 私有网络
        "192.168.0.0/16" // 私有网络
    },
}
```

### 日志配置

提供灵活的日志配置选项：

```go
// 使用JSON格式，DEBUG级别日志
turn.ConfigureLogger("json", "debug")

// 使用文本格式，INFO级别日志
turn.ConfigureLogger("text", "info")

// 使用控制台格式，ERROR级别日志
turn.ConfigureLogger("console", "error")
```

## API参考

### 核心函数

- `turn.DefaultConfig() Config` - 返回具有合理默认值的配置
- `turn.DefaultConfigWithIP(externalIP string) (Config, error)` - 返回包含指定外部IP的默认配置
- `turn.Start(conf Config) (Server, error)` - 启动标准TURN服务器
- `turn.StartTLS(conf Config) (Server, error)` - 启动支持TLS的TURN服务器
- `turn.ConfigureLogger(format, level string)` - 配置日志系统

### 服务器接口

```go
type Server interface {
    // 生成用户凭证
    Credentials(id string, addr net.IP) (string, string)
    
    // 禁用用户
    // - 内部认证：从用户存储中删除凭证
    // - 外部认证：将用户ID添加到黑名单
    Disallow(username string)
    
    // 用户认证
    Authenticate(username, realm string, addr net.Addr) ([]byte, bool)
}
```

### IP提供者接口

```go
type Provider interface {
    Get() (net.IP, net.IP, error)
}
```

## 内部架构

### 组件关系

```
+----------------+     +----------------+
|   应用程序     |     | 命令行TURN工具 |
+----------------+     +----------------+
        |                      |
        v                      v
+-------------------------------+
|          turn 包              |
+-------------------------------+
|    Server    |    Config      |
+--------------+----------------+
|  Generator   | RelayAddressGen |
+--------------+----------------+
|         ipdns                  |
+--------------+----------------+
|   Static    |      DNS       |  Prober   |
+-------------+----------------+-----------+
         |
+--------v---------+
|    pion/turn 包  |
+------------------+
```

### 文件结构

- **config.go**: 配置结构体和相关方法
- **server.go**: 服务器核心实现，含内部认证和外部认证
- **server_tls.go**: TLS服务器实现
- **portrange.go**: 端口范围分配器
- **none.go**: 无端口限制分配器
- **utils.go**: 日志配置和工具函数
- **ipdns/**: IP地址提供者实现
  - **provider.go**: Provider接口定义
  - **static.go**: 静态IP提供者
  - **dns.go**: DNS解析IP提供者
- **turn-tls-server/**: 命令行TLS TURN服务器
  - **main.go**: 入口点和命令行参数处理

## 性能考量

- 默认情况下，TURN服务器在请求高峰期可能需要较多的系统资源
- 推荐在生产环境中使用以下配置：
  - 使用端口范围限制（`TurnPortRange`）避免端口耗尽
  - 启用黑名单（`TurnDenyPeers`）防止滥用
  - 使用外部认证模式（`TurnExternalSecret`）以便集成认证系统
  - 考虑黑名单清理策略，避免黑名单无限增长

## 故障排除

### 常见问题

1. **无法启动服务器**
   - 检查端口是否被占用
   - 确保拥有足够权限绑定端口（特别是小于1024的端口）

2. **客户端无法连接**
   - 确保防火墙允许UDP和TCP流量通过
   - 验证TLS证书是否有效
   - 检查黑名单是否误封了客户端IP

3. **日志问题**
   - 使用`-log-level debug`获取更详细的日志
   - 检查`LogFormat`配置是否正确

4. **认证问题**
   - 内部认证：检查用户凭证是否正确存储
   - 外部认证：确认时间戳未过期，用户ID未被禁用

## 贡献指南

欢迎对本项目做出贡献。在提交代码前，请确保：

1. 代码通过所有测试
2. 新功能包含适当的测试
3. 文档已更新
4. 代码符合Go的代码规范

## 许可证

本项目基于 MIT 许可证，详见LICENSE文件。 