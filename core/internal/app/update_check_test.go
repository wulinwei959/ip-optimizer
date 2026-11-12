package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hosts-optimizer/internal/update"
)

// 手动检查更新：首次触发返回 200 与检查结果；60 秒内重复触发返回 429；
// 超过间隔后可再次触发。测试环境关闭真实检查（不发起网络请求）。
func TestHandleUpdateCheck(t *testing.T) {
	t.Setenv("HO_UPDATE_CHECK", "off")
	a := &App{updateChecker: update.New("1.4.0")}

	req := httptest.NewRequest(http.MethodPost, "/api/update-check", nil)
	rec := httptest.NewRecorder()
	a.handleUpdateCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("首次检查应 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp["ok"] != true {
		t.Fatalf("ok 应为 true: %v", resp)
	}

	// 60 秒内重复触发应 429。
	rec = httptest.NewRecorder()
	a.handleUpdateCheck(rec, httptest.NewRequest(http.MethodPost, "/api/update-check", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("重复触发应 429，实际 %d: %s", rec.Code, rec.Body.String())
	}

	// 超过间隔后可再次触发。
	a.lastUpdateCheck = time.Now().Add(-2 * updateCheckMinInterval)
	rec = httptest.NewRecorder()
	a.handleUpdateCheck(rec, httptest.NewRequest(http.MethodPost, "/api/update-check", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("超过间隔后应再次 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
}

// /api/update-check 走 admin 包装：缺令牌应 401。
func TestHandleUpdateCheckRequiresToken(t *testing.T) {
	a := &App{adminToken: "secret", updateChecker: update.New("1.4.0")}
	h := a.admin(a.handleUpdateCheck)

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/api/update-check", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("缺令牌应 401，实际 %d", rec.Code)
	}
}
