package turn

import (
	"fmt"
	"log/slog"
)

// Result 提供更优雅的错误处理和链式操作
type Result[T any] struct {
	value T
	err   error
}

// NewResult 创建一个新的结果
func NewResult[T any](value T, err error) *Result[T] {
	return &Result[T]{value: value, err: err}
}

// Ok 创建一个成功的结果
func Ok[T any](value T) *Result[T] {
	return &Result[T]{value: value}
}

// Err 创建一个错误的结果
func Err[T any](err error) *Result[T] {
	var zero T
	return &Result[T]{value: zero, err: err}
}

// IsOk 检查结果是否成功
func (r *Result[T]) IsOk() bool {
	return r.err == nil
}

// IsErr 检查结果是否失败
func (r *Result[T]) IsErr() bool {
	return r.err != nil
}

// Unwrap 解包结果，如果有错误则panic
func (r *Result[T]) Unwrap() T {
	if r.err != nil {
		panic(r.err)
	}
	return r.value
}

// UnwrapOr 解包结果，如果有错误则返回默认值
func (r *Result[T]) UnwrapOr(defaultValue T) T {
	if r.err != nil {
		return defaultValue
	}
	return r.value
}

// UnwrapOrElse 解包结果，如果有错误则调用函数获取默认值
func (r *Result[T]) UnwrapOrElse(fn func(error) T) T {
	if r.err != nil {
		return fn(r.err)
	}
	return r.value
}

// Map 将结果映射为另一种类型
func Map[T, U any](r *Result[T], fn func(T) U) *Result[U] {
	if r.err != nil {
		return Err[U](r.err)
	}
	return Ok(fn(r.value))
}

// MapErr 映射错误
func (r *Result[T]) MapErr(fn func(error) error) *Result[T] {
	if r.err != nil {
		return &Result[T]{value: r.value, err: fn(r.err)}
	}
	return r
}

// AndThen 链式操作，只有成功时才执行
func AndThen[T, U any](r *Result[T], fn func(T) *Result[U]) *Result[U] {
	if r.err != nil {
		return Err[U](r.err)
	}
	return fn(r.value)
}

// OrElse 如果失败则尝试另一个操作
func (r *Result[T]) OrElse(fn func(error) *Result[T]) *Result[T] {
	if r.err != nil {
		return fn(r.err)
	}
	return r
}

// LogError 记录错误日志（如果有错误）
func (r *Result[T]) LogError(msg string, args ...any) *Result[T] {
	if r.err != nil {
		args = append(args, "error", r.err)
		slog.Error(msg, args...)
	}
	return r
}

// LogSuccess 记录成功日志（如果成功）
func (r *Result[T]) LogSuccess(msg string, args ...any) *Result[T] {
	if r.err == nil {
		slog.Info(msg, args...)
	}
	return r
}

// ServerResult 服务器操作结果的类型别名
type ServerResult = Result[Server]

// ConfigResult 配置操作结果的类型别名
type ConfigResult = Result[Config]

// 便捷的构造函数
func ServerOk(server Server) *ServerResult {
	return Ok(server)
}

func ServerErr(err error) *ServerResult {
	return Err[Server](err)
}

func ConfigOk(config Config) *ConfigResult {
	return Ok(config)
}

func ConfigErr(err error) *ConfigResult {
	return Err[Config](err)
}

// 结果组合器
type ResultBuilder struct {
	results []error
}

func NewResultBuilder() *ResultBuilder {
	return &ResultBuilder{
		results: make([]error, 0),
	}
}

func (rb *ResultBuilder) Add(r *Result[any]) *ResultBuilder {
	if r.err != nil {
		rb.results = append(rb.results, r.err)
	}
	return rb
}

func (rb *ResultBuilder) AddError(err error) *ResultBuilder {
	if err != nil {
		rb.results = append(rb.results, err)
	}
	return rb
}

func (rb *ResultBuilder) Build() error {
	if len(rb.results) == 0 {
		return nil
	}

	if len(rb.results) == 1 {
		return rb.results[0]
	}

	// 合并多个错误
	var errMsg string
	for i, err := range rb.results {
		if i == 0 {
			errMsg = err.Error()
		} else {
			errMsg += "; " + err.Error()
		}
	}

	return fmt.Errorf("多个错误: %s", errMsg)
}

// Try 函数提供类似Rust的?操作符功能
func Try[T any](value T, err error) *Result[T] {
	return NewResult(value, err)
}

// Must 函数在错误时panic，用于必须成功的操作
func Must[T any](value T, err error) T {
	if err != nil {
		panic(fmt.Errorf("必须成功的操作失败: %w", err))
	}
	return value
}
