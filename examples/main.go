package main

import (
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/darkit/turn"
	"github.com/darkit/turn/ipdns"
)

// 定义命令行参数
type cmdArgs struct {
	tlsCertFile      string
	tlsKeyFile       string
	turnAddress      string
	turnPortRange    string
	turnExternalIP   string
	turnExternalPort string
	turnSecret       string
	turnDenyPeers    string
	logFormat        string
	logLevel         string
}

func main() {
	// 解析命令行参数
	args := parseCmdArgs()

	// 初始化日志
	turn.ConfigureLogger(args.logFormat, args.logLevel)

	// 解析外部IP
	var externalIPs []string
	if args.turnExternalIP != "" {
		externalIPs = strings.Split(args.turnExternalIP, ",")
	}

	// 解析拒绝的对等方IP
	var denyPeers []string
	if args.turnDenyPeers != "" {
		denyPeers = strings.Split(args.turnDenyPeers, ",")
	} else {
		denyPeers = []string{"0.0.0.0/8", "127.0.0.1/8", "::/128", "::1/128", "fe80::/10"}
	}

	// 创建IP地址提供者
	ipProvider, err := createIPProvider(externalIPs)
	if err != nil {
		slog.Error("无法创建IP地址提供者", "error", err)
		os.Exit(1)
	}

	// 创建TURN服务器配置
	config := turn.Config{
		TLSEnabled:         true,
		TLSCertFile:        args.tlsCertFile,
		TLSKeyFile:         args.tlsKeyFile,
		TurnAddress:        args.turnAddress,
		TurnPortRange:      args.turnPortRange,
		TurnExternalIP:     externalIPs,
		TurnExternalPort:   args.turnExternalPort,
		TurnExternalSecret: args.turnSecret,
		TurnDenyPeers:      denyPeers,
		LogFormat:          args.logFormat,
		LogLevel:           args.logLevel,
		TurnIPProvider:     ipProvider,
		TurnExternal:       args.turnSecret != "",
	}

	// 解析CIDR
	if err := config.ParseCIDRs(); err != nil {
		slog.Error("无法解析拒绝的对等方IP", "error", err)
		os.Exit(1)
	}

	// 启动TURN服务器
	server, err := turn.StartTLS(config)
	if err != nil {
		slog.Error("无法启动TURN服务器", "error", err)
		os.Exit(1)
	}

	slog.Info("TURN服务器已启动，等待连接...")

	// 等待中断信号
	waitForInterrupt()

	// 关闭服务器
	slog.Info("正在关闭服务器...")
	_ = server
}

// 解析命令行参数
func parseCmdArgs() cmdArgs {
	var args cmdArgs

	flag.StringVar(&args.tlsCertFile, "tls-cert", "", "TLS证书文件路径")
	flag.StringVar(&args.tlsKeyFile, "tls-key", "", "TLS私钥文件路径")
	flag.StringVar(&args.turnAddress, "turn-address", ":3478", "TURN服务器监听地址")
	flag.StringVar(&args.turnPortRange, "turn-port-range", "", "TURN端口范围，格式为'min:max'")
	flag.StringVar(&args.turnExternalIP, "turn-external-ip", "", "TURN服务器外部IP地址，多个地址用逗号分隔")
	flag.StringVar(&args.turnExternalPort, "turn-external-port", "3478", "TURN服务器外部端口")
	flag.StringVar(&args.turnSecret, "turn-secret", "", "外部TURN认证密钥，如果提供则启用外部认证模式")
	flag.StringVar(&args.turnDenyPeers, "turn-deny-peers", "", "拒绝的对等方IP范围，多个范围用逗号分隔")
	flag.StringVar(&args.logFormat, "log-format", "text", "日志格式：text, json, console")
	flag.StringVar(&args.logLevel, "log-level", "info", "日志级别：debug, info, warn, error")

	flag.Parse()

	// 验证TLS证书和密钥文件
	if args.tlsCertFile == "" || args.tlsKeyFile == "" {
		slog.Error("必须提供TLS证书和私钥文件")
		os.Exit(1)
	}

	// 检查文件是否存在
	if !fileExists(args.tlsCertFile) {
		slog.Error("TLS证书文件不存在", "file", args.tlsCertFile)
		os.Exit(1)
	}
	if !fileExists(args.tlsKeyFile) {
		slog.Error("TLS私钥文件不存在", "file", args.tlsKeyFile)
		os.Exit(1)
	}

	return args
}

// 创建IP地址提供者
func createIPProvider(externalIPs []string) (ipdns.Provider, error) {
	if len(externalIPs) > 0 {
		return ipdns.NewStatic(externalIPs)
	}
	return ipdns.NewProber("stun.zishuo.net:3478", true)
}

// 等待中断信号
func waitForInterrupt() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}

// 检查文件是否存在
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
