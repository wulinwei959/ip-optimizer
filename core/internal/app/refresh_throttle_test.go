package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hosts-optimizer/internal/update"
)

// TestStartRefreshThrottle 验证手动刷新的 10 秒限流与运行中任务复用。
func TestStartRefreshThrottle(t *testing.T) {
	a := &App{}

	// 无任务且刚刷新过 → 限流（不启动 goroutine）。
	a.lastRefresh = time.Now()
	if _, _, throttled := a.startRefresh(nil); !throttled {
		t.Fatal("距上次刷新不足 10 秒应限流")
	}

	// 有任务在跑 → 复用，不受限流影响。
	a.refreshTask = &refreshTask{ID: "running-1", State: refreshRunning}
	if id, reused, throttled := a.startRefresh(nil); throttled || !reused || id != "running-1" {
		t.Fatalf("运行中任务应复用: id=%s reused=%v throttled=%v", id, reused, throttled)
	}

	// 任务已结束且距上次刷新超过间隔 → 正常启动。
	// HO_CONFIG 指向空目录：runRefresh 会因缺配置快速失败，不发起网络探测。
	t.Setenv("HO_CONFIG", t.TempDir())
	a.refreshTask = &refreshTask{State: refreshDone}
	a.lastRefresh = time.Now().Add(-2 * refreshMinInterval)
	if _, reused, throttled := a.startRefresh(nil); throttled || reused {
		t.Fatalf("超过间隔应正常启动: reused=%v throttled=%v", reused, throttled)
	}
}

// TestHealthzUpdateFields 验证 /healthz 暴露新版本检查字段。
func TestHealthzUpdateFields(t *testing.T) {
	t.Setenv("HO_UPDATE_CHECK", "off")
	a := &App{
		version:       "1.3.0",
		startedAt:     time.Now(),
		updateChecker: update.New("1.3.0"),
	}
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	a.handleHealthz(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz 应 200，实际 %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 healthz 失败: %v", err)
	}
	if resp["version"] != "1.3.0" {
		t.Fatalf("version 字段不符: %v", resp["version"])
	}
	if _, ok := resp["update_available"]; !ok {
		t.Fatal("healthz 应含 update_available 字段")
	}
	if _, ok := resp["latest_version"]; !ok {
		t.Fatal("healthz 应含 latest_version 字段")
	}
	if resp["update_available"] != false {
		t.Fatalf("禁用检查时 update_available 应为 false: %v", resp["update_available"])
	}
	// 扩展缓存计数字段也应存在。
	if _, ok := resp["expand_cache_hits"]; !ok {
		t.Fatal("healthz 应含 expand_cache_hits 字段")
	}
}
