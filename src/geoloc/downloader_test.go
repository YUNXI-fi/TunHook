package geoloc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDownloadSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	data, attempts, err := Download(context.Background(), srv.Client(), srv.URL, DefaultMaxRetries)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("data = %q", data)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
}

func TestDownloadRetryThenSuccess(t *testing.T) {
	oldBase, oldMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, time.Millisecond
	defer func() { retryBaseDelay, retryMaxDelay = oldBase, oldMax }()

	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	data, attempts, err := Download(context.Background(), srv.Client(), srv.URL, 3)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(data) != "ok" {
		t.Errorf("data = %q", data)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestDownloadNoRetryOn4xx(t *testing.T) {
	oldBase, oldMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, time.Millisecond
	defer func() { retryBaseDelay, retryMaxDelay = oldBase, oldMax }()

	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, attempts, err := Download(context.Background(), srv.Client(), srv.URL, 3)
	if err == nil {
		t.Fatal("404 应返回错误")
	}
	if attempts != 1 {
		t.Errorf("404 attempts = %d, want 1（4xx 不重试）", attempts)
	}
}

func TestDownloadRetryExhausted(t *testing.T) {
	oldBase, oldMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = time.Millisecond, time.Millisecond
	defer func() { retryBaseDelay, retryMaxDelay = oldBase, oldMax }()

	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, attempts, err := Download(context.Background(), srv.Client(), srv.URL, 2)
	if err == nil {
		t.Fatal("持续 5xx 应返回错误")
	}
	if attempts != 3 { // 首次 + 2 次重试
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

// TestDownloadCanceled 取消 ctx 应立即中断下载（对应关服场景：不再等待超时）。
func TestDownloadCanceled(t *testing.T) {
	blocked := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-blocked // 一直不响应
	}))
	defer func() {
		close(blocked)
		srv.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := Download(ctx, srv.Client(), srv.URL, DefaultMaxRetries)
	if err == nil {
		t.Fatal("取消后应返回错误")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("取消后耗时 %v，未及时中断", elapsed)
	}
}

func TestBackoffDelay(t *testing.T) {
	oldBase, oldMax := retryBaseDelay, retryMaxDelay
	retryBaseDelay, retryMaxDelay = 500*time.Millisecond, 8*time.Second
	defer func() { retryBaseDelay, retryMaxDelay = oldBase, oldMax }()

	if d := backoffDelay(1); d != 500*time.Millisecond {
		t.Errorf("backoffDelay(1) = %v", d)
	}
	if d := backoffDelay(2); d != time.Second {
		t.Errorf("backoffDelay(2) = %v", d)
	}
	if d := backoffDelay(3); d != 2*time.Second {
		t.Errorf("backoffDelay(3) = %v", d)
	}
	if d := backoffDelay(10); d != 8*time.Second {
		t.Errorf("backoffDelay(10) 应封顶 8s, got %v", d)
	}
}
