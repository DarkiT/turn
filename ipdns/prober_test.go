package ipdns

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"
)

// TestProberGetFetchAndCache 验证 STUN 探测能够获取有效的外部 IP 并且支持缓存。
func TestProberGetFetchAndCache(t *testing.T) {
	addr, stop := startMockStunServer(t)
	defer stop()

	prober, err := NewProber(addr, false)
	if err != nil {
		t.Fatalf("创建 STUN 探测器失败: %v", err)
	}

	v4, v6, err := prober.Get()
	if err != nil {
		t.Fatalf("首次探测失败: %v", err)
	}
	if v4 == nil {
		t.Fatal("首次探测未返回 IPv4 地址")
	}
	if expected := net.ParseIP("127.0.0.1"); !v4.Equal(expected) {
		t.Fatalf("期望获得 %s，实际为 %s", expected, v4)
	}
	if v6 != nil {
		t.Fatalf("本测试仅返回 IPv4，应当没有 IPv6，实际得到 %v", v6)
	}

	// 停止 STUN 服务器后再次获取，验证缓存读取。
	stop()

	cachedV4, cachedV6, err := prober.Get()
	if err != nil {
		t.Fatalf("缓存读取失败: %v", err)
	}
	if cachedV4 == nil || !cachedV4.Equal(v4) {
		t.Fatalf("缓存的 IPv4 不正确，期望 %v 实际 %v", v4, cachedV4)
	}
	if cachedV6 != nil {
		t.Fatalf("缓存读取不应返回 IPv6，实际得到 %v", cachedV6)
	}
}

// TestProberGetIPv6 验证 STUN 探测在 IPv6 环境下能够返回 IPv6 地址。
func TestProberGetIPv6(t *testing.T) {
	addr, stop, ok := startMockStunServerV6()
	if !ok {
		t.Skip("系统不支持 IPv6 回环监听，跳过 IPv6 探测测试")
		return
	}
	defer stop()

	prober, err := NewProber(addr, false)
	if err != nil {
		t.Fatalf("创建 IPv6 STUN 探测器失败: %v", err)
	}

	v4, v6, err := prober.Get()
	if err != nil {
		t.Fatalf("IPv6 探测失败: %v", err)
	}
	if v4 != nil {
		t.Fatalf("IPv6 测试不应返回 IPv4，实际得到 %v", v4)
	}
	if v6 == nil {
		t.Fatal("IPv6 探测未返回 IPv6 地址")
	}
	if expected := net.ParseIP("::1"); !v6.Equal(expected) {
		t.Fatalf("期望 IPv6 地址为 %s，实际为 %s", expected, v6)
	}
}

func startMockStunServer(t *testing.T) (string, func()) {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 STUN 模拟服务器失败: %v", err)
	}

	done := make(chan struct{})
	var once sync.Once

	go func() {
		buffer := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				select {
				case <-done:
					return
				default:
				}

				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				continue
			}

			request := stun.New()
			request.Raw = make([]byte, n)
			copy(request.Raw, buffer[:n])
			if err := request.Decode(); err != nil {
				continue
			}
			if request.Type != stun.BindingRequest {
				continue
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}

			response := stun.New()
			response.Type = stun.BindingSuccess
			response.TransactionID = request.TransactionID
			if err := (stun.XORMappedAddress{IP: udpAddr.IP, Port: udpAddr.Port}).AddTo(response); err != nil {
				continue
			}
			response.Encode()
			_, _ = conn.WriteTo(response.Raw, addr)
		}
	}()

	stop := func() {
		once.Do(func() {
			close(done)
			_ = conn.Close()
		})
	}

	return conn.LocalAddr().String(), stop
}

func startMockStunServerV6() (string, func(), bool) {
	conn, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		return "", func() {}, false
	}

	done := make(chan struct{})
	var once sync.Once

	go func() {
		buffer := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				select {
				case <-done:
					return
				default:
				}

				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				continue
			}

			request := stun.New()
			request.Raw = make([]byte, n)
			copy(request.Raw, buffer[:n])
			if err := request.Decode(); err != nil {
				continue
			}
			if request.Type != stun.BindingRequest {
				continue
			}

			udpAddr, ok := addr.(*net.UDPAddr)
			if !ok {
				continue
			}

			response := stun.New()
			response.Type = stun.BindingSuccess
			response.TransactionID = request.TransactionID
			if err := (stun.XORMappedAddress{IP: udpAddr.IP, Port: udpAddr.Port}).AddTo(response); err != nil {
				continue
			}
			response.Encode()
			_, _ = conn.WriteTo(response.Raw, addr)
		}
	}()

	stop := func() {
		once.Do(func() {
			close(done)
			_ = conn.Close()
		})
	}

	return conn.LocalAddr().String(), stop, true
}
