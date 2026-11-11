package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsserver"
	"hosts-optimizer/internal/output"
	"hosts-optimizer/internal/store"
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

// 管理端点必须校验令牌；订阅端点与首页保持开放。
func TestAdminGuard(t *testing.T) {
	a := &App{adminToken: "s3cret"}
	h := a.admin(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/logs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("缺令牌时状态码 = %d, want 401", rec.Code)
	}

	for _, tc := range []struct {
		name string
		set  func(*http.Request)
	}{
		{"X-Admin-Token 头", func(r *http.Request) { r.Header.Set("X-Admin-Token", "s3cret") }},
		{"Bearer 头", func(r *http.Request) { r.Header.Set("Authorization", "Bearer s3cret") }},
		{"query 参数", func(r *http.Request) {
			r.URL.RawQuery = "token=s3cret"
		}},
	} {
		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
		tc.set(req)
		h(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: 状态码 = %d, want 204", tc.name, rec.Code)
		}
	}

	// 令牌错误时仍然拒绝。
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/logs", nil)
	req.Header.Set("X-Admin-Token", "s3cret-typo")
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("错误令牌状态码 = %d, want 401", rec.Code)
	}
}

// 未设置 HO_ADMIN_TOKEN 时自动生成；设置了就用配置值。
func TestResolveAdminToken(t *testing.T) {
	t.Setenv("HO_ADMIN_TOKEN", "from-env")
	if got := resolveAdminToken(); got != "from-env" {
		t.Fatalf("应使用环境变量，得到 %q", got)
	}
	t.Setenv("HO_ADMIN_TOKEN", "   ")
	tok := resolveAdminToken()
	if len(tok) != 48 || strings.ContainsAny(tok, " \t\r\n") {
		t.Fatalf("自动生成的令牌应为 48 位 hex，得到 %q", tok)
	}
}

// 本轮全灭时，磁盘上保留的上一轮产物必须继续可读，而不是 503。
func TestServeFallsBackToRetainedProduct(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(hosts, []byte("1.1.1.1 old.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &App{
		hostsPath: hosts,
		aghPath:   filepath.Join(dir, "agh.txt"),
		snap: &output.Snapshot{
			Ready: false, Modified: time.Now(),
			Hosts: []byte("# 本轮无有效 IP\n"), HostsETag: output.ETag([]byte("# 本轮无有效 IP\n")),
		},
	}

	rec := httptest.NewRecorder()
	a.serve(rec, httptest.NewRequest(http.MethodGet, "/hosts.txt", nil), "hosts")
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200（应服务磁盘保留的旧产物）: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "1.1.1.1") {
		t.Fatalf("应返回磁盘上保留的旧产物，实际: %s", rec.Body.String())
	}

	// 磁盘上也没有产物时才返回 503（首次启动、尚未产生任何有效 IP）。
	b := &App{hostsPath: filepath.Join(dir, "missing.txt"),
		snap: &output.Snapshot{Ready: false}}
	rec = httptest.NewRecorder()
	b.serve(rec, httptest.NewRequest(http.MethodGet, "/hosts.txt", nil), "hosts")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("无旧产物时状态码 = %d, want 503", rec.Code)
	}
}

// 自适应探测面：常规轮次只测当前 IP + 前 N 个挑战者，每 K 轮全量。
func TestProbeSetAdaptive(t *testing.T) {
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"}

	if got := probeSet(ips, nil, 5, 6, 0); len(got) != len(ips) {
		t.Fatalf("无历史时应全量扫描，得到 %v", got)
	}
	st := &store.DomainState{IP: "1.1.1.1", Candidates: []store.Candidate{
		{IP: "1.1.1.1", LatencyMS: 10}, {IP: "2.2.2.2", LatencyMS: 20},
	}}
	if got := probeSet(ips, st, 5, 6, 6); len(got) != len(ips) {
		t.Fatalf("每 K 轮应全量扫描，得到 %v", got)
	}
	if got := probeSet(ips[:3], st, 5, 6, 3); len(got) != 3 {
		t.Fatalf("候选数不超过上限时应全量，得到 %v", got)
	}

	got := probeSet(ips, st, 2, 6, 3)
	want := []string{"1.1.1.1", "2.2.2.2"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("常规轮次探测面 = %v, want %v", got, want)
	}

	// 当前 IP 不在本轮 DNS 结果里也要探测：它是正在生效的值，必须先确认它还活。
	st2 := &store.DomainState{IP: "9.9.9.9", Candidates: []store.Candidate{{IP: "2.2.2.2", LatencyMS: 5}}}
	got = probeSet(ips, st2, 1, 6, 3)
	if len(got) != 2 || got[0] != "9.9.9.9" || got[1] != "2.2.2.2" {
		t.Fatalf("应包含当前 IP 与挑战者，得到 %v", got)
	}
}

// 域名多到超过单行上限时必须拆成多行，且每行都保持 AGH 语法。
func TestAghUpstreamLinesSplitLongList(t *testing.T) {
	a := &App{dnsSrv: dnsserver.New("127.0.0.1:18053"), dnsListen: "127.0.0.1:18053"}
	doms := make([]config.Domain, 0, 100)
	for i := 0; i < 100; i++ {
		doms = append(doms, config.Domain{Name: fmt.Sprintf("d%02d.example.com", i)})
	}
	a.updateDNSFamilies(doms)

	lines := a.aghUpstreamLines()
	if len(lines) < 2 {
		t.Fatalf("100 个域名应拆成多行，实际 %d 行", len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "[/") || !strings.HasSuffix(line, "/]127.0.0.1:18053") {
			t.Fatalf("行格式不正确: %s", line)
		}
		if len(line) > maxAghLineBytes {
			t.Fatalf("单行超过长度上限: %d 字节", len(line))
		}
	}

	// 拆行后域名总数不应丢失。
	total := 0
	for _, line := range lines {
		body := strings.TrimSuffix(strings.TrimPrefix(line, "[/"), "/]127.0.0.1:18053")
		total += len(strings.Split(body, "/"))
	}
	if total != 100 {
		t.Fatalf("拆行后域名总数不符: %d", total)
	}
}
