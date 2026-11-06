package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestParseExpandSources(t *testing.T) {
	got, err := parseExpandSources([]string{"ct", "wordlist", "rules", "CT"})
	if err != nil {
		t.Fatalf("合法来源不应报错: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应去重为 3 个来源，实际 %d 个: %v", len(got), got)
	}

	if _, err := parseExpandSources([]string{"dns"}); err == nil {
		t.Fatal("非法来源应返回错误")
	}

	empty, err := parseExpandSources(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("空列表应返回空结果且不报错，实际 %v, %v", empty, err)
	}
}

func TestHandleExpandRejectsNonPost(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodGet, "/api/expand", nil)
	rec := httptest.NewRecorder()

	a.handleExpand(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("期望 405，实际 %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("期望 Allow: POST，实际 %q", allow)
	}
}

func TestHandleExpandRequiresJSONContentType(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodPost, "/api/expand", strings.NewReader(`{"domain":"github.com"}`))
	rec := httptest.NewRecorder()

	a.handleExpand(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("期望 415，实际 %d", rec.Code)
	}
}

// 回归保护：stop 脚本不能用 pkill -f 模糊匹配应用名。
// cmd/main 自身路径也包含 hosts-optimizer，模糊匹配会把执行 stop 的脚本一起杀掉，
// 应用中心会收到非零退出码并报 10350，表现为“进程已停止但操作失败”。
func TestLifecycleStopDoesNotUseBroadPkill(t *testing.T) {
	script, err := os.ReadFile("../../../deploy/fnos-native-fpk/cmd/common")
	if err != nil {
		t.Fatalf("读取生命周期脚本失败: %v", err)
	}
	body := string(script)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, `pkill -f "hosts-optimizer"`) {
			t.Fatal("stop 脚本不得使用 pkill -f 模糊匹配应用名")
		}
	}
	if !strings.Contains(body, "pidof hosts-optimizer") && !strings.Contains(body, "pgrep -x hosts-optimizer") {
		t.Fatal("stop 脚本应使用进程名精确匹配作为兜底清理")
	}
}
