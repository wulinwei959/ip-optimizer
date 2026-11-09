package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsserver"
	"hosts-optimizer/internal/output"
)

func TestMergeEntriesKeepsUntouched(t *testing.T) {
	existing := []output.StatusDomain{
		{Name: "a.com", IP: "1.1.1.1", LatencyMS: 10, Candidates: 2, Validated: 1, Reason: "保持"},
		{Name: "b.com", IP: "2.2.2.2", LatencyMS: 20, Candidates: 1, Validated: 0, Reason: "失败"},
	}
	refreshed := []output.Entry{
		{Name: "b.com", IP: "3.3.3.3", LatencyMS: 15, Candidates: 2, Validated: 1, Reason: "切换"},
		{Name: "c.com", IP: "4.4.4.4", LatencyMS: 5, Candidates: 1, Validated: 1, Reason: "新增"},
	}
	got := mergeEntries(existing, refreshed)
	if len(got) != 3 {
		t.Fatalf("合并后应有 3 条，实际 %d", len(got))
	}
	if got[0].Name != "a.com" || got[0].IP != "1.1.1.1" || got[0].Validated != 1 {
		t.Fatalf("未刷新域名应保持不变: %+v", got[0])
	}
	if got[1].Name != "b.com" || got[1].IP != "3.3.3.3" || got[1].Validated != 1 {
		t.Fatalf("刷新域名应被覆盖: %+v", got[1])
	}
	if got[2].Name != "c.com" || got[2].IP != "4.4.4.4" {
		t.Fatalf("新域名应追加到末尾: %+v", got[2])
	}
}

func TestSelectTargets(t *testing.T) {
	all := []config.Target{
		{Name: "a.com", Port: 443},
		{Name: "b.com", Port: 8443},
	}
	got := selectTargets(all, map[string]bool{"b.com": true, "x.com": true}, config.Defaults{ProbePort: 443})
	if len(got) != 2 {
		t.Fatalf("目标数 = %d, want 2", len(got))
	}
	if got[0].Name != "b.com" || got[0].Port != 8443 {
		t.Fatalf("配置内域名应沿用原参数: %+v", got[0])
	}
	if got[1].Name != "x.com" || got[1].Port != 443 || got[1].SNI != "x.com" {
		t.Fatalf("配置外域名应按默认参数补齐: %+v", got[1])
	}
}

func TestNormalizeDomainNames(t *testing.T) {
	got := normalizeDomainNames([]string{" A.com ", "a.com", "", "b.com"})
	if len(got) != 2 || got[0] != "a.com" || got[1] != "b.com" {
		t.Fatalf("去重/小写/去空格结果不符: %v", got)
	}
}

func TestWithPendingDomains(t *testing.T) {
	existing := []output.StatusDomain{
		{Name: "github.com", IP: "1.1.1.1", Validated: 1, Reason: "保持"},
	}
	cfg := []config.Domain{
		{Name: "github.com"},
		{Name: "example.com"},
		{Name: " "},
		{Name: "new.com"},
		{Name: "old.com", Disabled: true},
	}
	got := mergeDomainViews(existing, cfg)
	if len(got) != 4 {
		t.Fatalf("合并后应有 4 条，实际 %d", len(got))
	}
	if got[0].Name != "github.com" || got[0].IP != "1.1.1.1" {
		t.Fatalf("已有域名不应被覆盖: %+v", got[0])
	}
	if got[1].Name != "example.com" || !got[1].Pending || got[1].Reason != "待探测" || got[1].IP != "" {
		t.Fatalf("新域名应标记待探测: %+v", got[1])
	}
	if got[2].Name != "new.com" {
		t.Fatalf("新域名顺序不符: %+v", got[2])
	}
	if got[3].Name != "old.com" || !got[3].Disabled || got[3].Reason != "已禁用" {
		t.Fatalf("禁用域名应标记已禁用: %+v", got[3])
	}
}

func TestIsWildcardHost(t *testing.T) {
	cases := map[string]bool{
		"0.0.0.0":      true,
		"::":           true,
		"":             false,
		"127.0.0.1":    false,
		"192.168.3.59": false,
	}
	for host, want := range cases {
		if got := isWildcardHost(host); got != want {
			t.Fatalf("isWildcardHost(%q)=%v，期望 %v", host, got, want)
		}
	}
}

// 监听 0.0.0.0 时，分流行必须替换成容器可达的主机 IP，不能原样输出 0.0.0.0。
func TestAghUpstreamLineReplacesWildcard(t *testing.T) {
	a := &App{dnsSrv: dnsserver.New("0.0.0.0:18053"), dnsListen: "0.0.0.0:18053"}
	a.updateDNSFamilies([]config.Domain{{Name: "github.com"}})

	line := a.aghUpstreamLine()
	if line == "" {
		t.Fatal("分流行不应为空")
	}
	if strings.Contains(line, "0.0.0.0") {
		t.Fatalf("分流行不应包含通配地址: %s", line)
	}
	if !strings.HasSuffix(line, ":18053") {
		t.Fatalf("分流行端口不正确: %s", line)
	}
	if !strings.HasPrefix(line, "[/github.com/]") {
		t.Fatalf("分流行域名段不正确: %s", line)
	}
}

// 改监听地址后，应答器实际绑定地址与生成的分流行必须同步。
func TestApplyDNSListenSyncsRule(t *testing.T) {
	a := &App{dnsBaseCtx: context.Background()}
	a.updateDNSFamilies([]config.Domain{{Name: "github.com"}})

	a.applyDNSListen("127.0.0.1:0")
	defer a.applyDNSListen("")

	srv, _ := a.dnsServerSnapshot()
	if srv == nil {
		t.Fatal("监听未启动")
	}
	for i := 0; i < 400 && !srv.Started(); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !srv.Started() {
		t.Fatal("监听未就绪")
	}

	line := a.aghUpstreamLine()
	if !strings.HasPrefix(line, "[/github.com/]127.0.0.1:") {
		t.Fatalf("分流行主机段不正确: %s", line)
	}
	// 端口 0 由系统分配，分流行必须用真实端口而不是 0。
	if strings.HasSuffix(line, ":0") {
		t.Fatalf("分流行应使用实际绑定端口: %s", line)
	}
	if got := strings.TrimPrefix(line, "[/github.com/]"); !strings.HasSuffix(srv.Addr(), got) {
		t.Fatalf("分流行与监听地址不同步: rule=%s addr=%s", got, srv.Addr())
	}
}
