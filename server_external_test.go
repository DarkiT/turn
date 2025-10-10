package turn

import (
	"net"
	"strings"
	"testing"

	"github.com/darkit/turn/ipdns"
)

// TestConfigPrepareAutoStaticProvider 验证 PrepareForStart 会在仅提供外部 IP 时自动补全静态提供者。
func TestConfigPrepareAutoStaticProvider(t *testing.T) {
	config := DefaultConfig()
	config.TurnExternalIP = []string{"203.0.113.5"}

	if err := config.PrepareForStart(); err != nil {
		t.Fatalf("期望配置预处理成功，实际失败: %v", err)
	}

	if config.TurnIPProvider == nil {
		t.Fatal("配置预处理后缺少 IP 提供者")
	}

	if _, ok := config.TurnIPProvider.(*ipdns.Static); !ok {
		t.Fatalf("期望自动注入静态 IP 提供者，实际类型为 %T", config.TurnIPProvider)
	}
}

// TestExternalServerCredentialsAndBlacklist 验证外部认证服务器的凭证生成与黑名单逻辑。
func TestExternalServerCredentialsAndBlacklist(t *testing.T) {
	config := DefaultConfig()
	provider, err := ipdns.NewStatic([]string{"198.51.100.8"})
	if err != nil {
		t.Fatalf("创建静态 IP 提供者失败: %v", err)
	}

	config.TurnIPProvider = provider
	config.TurnExternalSecret = strings.Repeat("s", 16)

	if err := config.PrepareForStart(); err != nil {
		t.Fatalf("配置预处理失败: %v", err)
	}

	server, err := createServerInstance(config)
	if err != nil {
		t.Fatalf("创建服务器实例失败: %v", err)
	}

	ext, ok := server.(*ExternalServer)
	if !ok {
		t.Fatalf("期望返回 ExternalServer，实际类型为 %T", server)
	}

	username, password := ext.Credentials("user-1", net.ParseIP("198.51.100.8"))
	if username == "" || password == "" {
		t.Fatalf("生成凭证失败: username=%q password=%q", username, password)
	}

	credentialIP := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 50000}
	if _, ok := ext.Authenticate(username, Realm, credentialIP); !ok {
		t.Fatal("凭证应当通过认证")
	}

	// 禁用完整用户名格式
	ext.Disallow(username)
	if _, ok := ext.Authenticate(username, Realm, credentialIP); ok {
		t.Fatal("禁用后认证不应通过")
	}

	// 测试直接使用用户 ID 禁用
	secondUsername, _ := ext.Credentials("user-2", net.ParseIP("198.51.100.8"))
	ext.Disallow("user-2")
	if _, ok := ext.Authenticate(secondUsername, Realm, credentialIP); ok {
		t.Fatal("通过用户 ID 禁用后认证不应通过")
	}
}
