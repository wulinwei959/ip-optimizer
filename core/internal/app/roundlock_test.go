package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// timedMutex 的限时获取语义：持锁时限时等待失败、解锁后可重取、立即试锁正确区分。
func TestTimedMutexTryLockTimeout(t *testing.T) {
	m := newTimedMutex()

	// 空锁时立即试锁成功并持有。
	if !m.tryLockTimeout(0) {
		t.Fatal("空锁时立即试锁应成功")
	}
	m.unlock()

	// 空锁时限时获取成功。
	if !m.tryLockTimeout(10*time.Millisecond) {
		t.Fatal("空锁时限时获取应成功")
	}
	m.unlock()

	// 重新持有后，限时短等待应失败。
	m.lock()
	if m.tryLockTimeout(5*time.Millisecond) {
		t.Fatal("持锁时短超时应失败")
	}
	// 超时等待后仍失败，且拿不到锁时返回 false 而非阻塞。
	start := time.Now()
	if m.tryLockTimeout(30*time.Millisecond) {
		t.Fatal("持锁时超时等待应失败")
	}
	if time.Since(start) < 20*time.Millisecond {
		t.Fatal("限时获取应实际等待到超时，而非立即返回")
	}
	m.unlock()
	if !m.tryLockTimeout(0) {
		t.Fatal("解锁后立即试锁应成功")
	}
}

// 周期任务拿不到锁应返回 errRoundBusy 且不触发任何探测。
func TestDoRoundLockBusy(t *testing.T) {
	a := &App{roundMu: newTimedMutex(), lastSchedule: 60}
	a.roundMu.lock()

	_, err := a.doRoundFor(context.Background(), nil, false, 10*time.Millisecond)
	if !errors.Is(err, errRoundBusy) {
		t.Fatalf("拿不到锁应返回 errRoundBusy，实际 %v", err)
	}
	if a.lockBusyCount.Load() != 1 {
		t.Fatalf("锁繁忙计数应为 1，实际 %d", a.lockBusyCount.Load())
	}
	// 解锁后应能正常进入（配置缺失会返回配置错误而非锁繁忙）。
	a.roundMu.unlock()
	t.Setenv("HO_CONFIG", t.TempDir())
	_, err = a.doRoundFor(context.Background(), nil, false, 10*time.Millisecond)
	if errors.Is(err, errRoundBusy) {
		t.Fatalf("解锁后不应再返回锁繁忙: %v", err)
	}
}

// 用户显式操作（手动切换 IP）在锁被长轮占用时应返回 409，而非无限排队。
func TestHandleSwitchConflictWhenLocked(t *testing.T) {
	a := &App{roundMu: newTimedMutex()}
	a.roundMu.lock()
	defer a.roundMu.unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/switch", strings.NewReader(`{"domain":"a.com","ip":"1.2.3.4"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.handleSwitch(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("锁被占用时状态码 = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}
