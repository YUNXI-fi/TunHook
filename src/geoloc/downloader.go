package geoloc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

const (
	// MaxDownloadSize 单个数据源文件大小上限（64MB）。
	MaxDownloadSize = 64 << 20
	// DefaultMaxRetries 默认最大重试次数。
	DefaultMaxRetries = 3
)

// 指数退避参数（包级变量以便测试缩短等待）。
var (
	retryBaseDelay = 500 * time.Millisecond
	retryMaxDelay  = 8 * time.Second
)

// Download 下载 URL 内容（64MB 上限），失败时按指数退避重试。
// 网络错误与 5xx/429 响应触发重试；4xx（除 429）不重试。
// ctx 取消（如关服）时立即中断请求与退避等待。
// 返回响应体、实际尝试次数与错误。
func Download(ctx context.Context, client *http.Client, u string, maxRetries int) ([]byte, int, error) {
	if client == nil {
		client = http.DefaultClient
	}
	attempt := 0
	for {
		attempt++
		data, err := downloadOnce(ctx, client, u)
		if err == nil {
			return data, attempt, nil
		}
		if attempt > maxRetries || !retryable(err) {
			return nil, attempt, err
		}
		delay := backoffDelay(attempt)
		select {
		case <-ctx.Done():
			return nil, attempt, ctx.Err()
		case <-time.After(delay):
		}
	}
}

// downloadOnce 执行一次下载请求并校验响应状态。
func downloadOnce(ctx context.Context, client *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, &downloadError{msg: err.Error(), retryable: true}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &downloadError{msg: err.Error(), retryable: true}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		limited := &io.LimitedReader{R: resp.Body, N: MaxDownloadSize}
		data, err := io.ReadAll(limited)
		if err != nil {
			return nil, &downloadError{msg: err.Error(), retryable: true}
		}
		if limited.N <= 0 {
			return nil, &downloadError{msg: "数据超过 64MB 上限"}
		}
		return data, nil
	}
	retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
	return nil, &downloadError{msg: fmt.Sprintf("HTTP %d", resp.StatusCode), retryable: retry}
}

// downloadError 携带是否可重试标记的错误。
type downloadError struct {
	msg       string
	retryable bool
}

func (e *downloadError) Error() string { return e.msg }

// retryable 判断错误是否可重试。
func retryable(err error) bool {
	if de, ok := err.(*downloadError); ok {
		return de.retryable
	}
	return true // 未知错误（如超时）默认重试
}

// backoffDelay 计算第 attempt 次重试前的等待时长（指数退避 + 封顶）。
func backoffDelay(attempt int) time.Duration {
	d := retryBaseDelay
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= retryMaxDelay {
			return retryMaxDelay
		}
	}
	if d > retryMaxDelay {
		return retryMaxDelay
	}
	return d
}

// downloadWithLogger 带日志的下载封装（供更新流程记录重试次数）。
func downloadWithLogger(ctx context.Context, logger *zap.Logger, client *http.Client, u string, maxRetries int) ([]byte, error) {
	data, attempts, err := Download(ctx, client, u, maxRetries)
	if err != nil {
		logger.Warn("数据源下载失败",
			zap.String("url", u),
			zap.Int("attempts", attempts),
			zap.Error(err),
		)
		return nil, err
	}
	if attempts > 1 {
		logger.Info("数据源下载重试成功",
			zap.String("url", u),
			zap.Int("attempts", attempts),
		)
	}
	return data, nil
}
