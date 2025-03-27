package turn

import (
	"crypto/rand"
	"log/slog"
	"math/big"
	"os"
	"strings"
)

func randString(length int) string {
	res := make([]byte, length)
	for i := range res {
		index := randIntn(len(tokenCharacters))
		res[i] = tokenCharacters[index]
	}
	return string(res)
}

var (
	tokenCharacters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_!@#$%^&*()){}\\/=+,.><")
	randReader      = rand.Reader
)

func randIntn(n int) int {
	max := big.NewInt(int64(n))
	res, err := rand.Int(randReader, max)
	if err != nil {
		panic("random source is not available")
	}
	return int(res.Int64())
}

// ConfigureLogger 根据配置初始化日志
// format: 日志格式，支持 "json", "text", "console"
// level: 日志级别，支持 "debug", "info", "warn", "error"
func ConfigureLogger(format, level string) {
	var handler slog.Handler

	// 设置日志格式
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level:     getLogLevel(level),
			AddSource: true,
		})
	case "text":
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     getLogLevel(level),
			AddSource: true,
		})
	default: // console
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level:     getLogLevel(level),
			AddSource: true,
		})
	}

	// 设置全局日志记录器
	slog.SetDefault(slog.New(handler))
}

// getLogLevel 获取日志级别
func getLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
