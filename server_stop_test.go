package turn

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/darkit/turn/ipdns"
)

// TestServerStopReleasesResources 验证 Stop 会释放监听端口且可重复调用。
func TestServerStopReleasesResources(t *testing.T) {
	config := DefaultConfig()
	config.TurnAddress = "127.0.0.1:0"

	provider, err := ipdns.NewStatic([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("创建静态 IP 提供者失败: %v", err)
	}
	config.TurnIPProvider = provider

	server, err := Start(config)
	if err != nil {
		t.Fatalf("启动服务器失败: %v", err)
	}

	runtime, ok := server.(*runtimeServer)
	if !ok {
		t.Fatalf("期望返回 *runtimeServer，实际类型为 %T", server)
	}

	addr := runtime.tcpListener.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := server.Stop(ctx); err != nil {
		t.Fatalf("首次停止服务器失败: %v", err)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("服务器停止后无法重新监听 %s: %v", addr, err)
	}
	_ = listener.Close()

	if err := server.Stop(context.Background()); err != nil {
		t.Fatalf("重复停止服务器失败: %v", err)
	}
}
