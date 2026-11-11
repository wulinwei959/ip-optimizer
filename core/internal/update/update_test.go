package update

import "testing"

// TestCompareVersions 验证版本比较：v 前缀、三段数值、相等与大小关系。
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.3.0", "v1.4.0", -1},
		{"v1.4.0", "1.4.1", -1},
		{"1.4.1", "v1.4.0", 1},
		{"v1.4.0", "1.4.0", 0},
		{"1.4.0", "1.4.0", 0},
		{"v2.0.0", "v1.9.9", 1},
		{"1.10.0", "1.9.0", 1}, // 数值比较而非字典序
		{"1.0.10", "1.0.9", 1},
		{"", "1.0.0", -1},
		{"1.4", "1.4.0", 0},         // 缺段按 0
		{"v1.4.0-beta", "1.4.0", 0}, // 预发布后缀被忽略（releases/latest 只返回正式版）
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCheckerDisabledNoop 验证 HO_UPDATE_CHECK=off 时 Checker 为 no-op。
func TestCheckerDisabledNoop(t *testing.T) {
	t.Setenv("HO_UPDATE_CHECK", "off")
	c := New("1.3.0")
	c.Check(nil) // 不应 panic，也不应发起请求
	latest, available, checkedAt := c.Status()
	if latest != "" || available || !checkedAt.IsZero() {
		t.Fatalf("禁用时 Status 应为零值: latest=%q available=%v", latest, available)
	}
}
