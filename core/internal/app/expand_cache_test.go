package app

import (
	"context"
	"testing"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/expand"
)

func expandOpts(sources ...expand.Source) expand.Options {
	return expand.Options{
		Sources:       sources,
		Concurrency:   10,
		Timeout:       10 * time.Second,
		MaxSubdomains: 50,
		ProbeDNS:      []string{"223.5.5.5"},
	}
}

func resolvedResults() []expand.Result {
	return []expand.Result{
		{Domain: "www.example.com", Source: expand.SourceWordlist, Resolved: true, IPs: []string{"1.1.1.1"}},
		{Domain: "api.example.com", Source: expand.SourceRules, Resolved: true, IPs: []string{"2.2.2.2", "3.3.3.3"}},
		// 未解析/空 IP 的条目应被 buildSubTargets 过滤掉。
		{Domain: "dead.example.com", Source: expand.SourceWordlist, Resolved: false},
		{Domain: "empty.example.com", Source: expand.SourceWordlist, Resolved: true},
	}
}

// 命中复用：TTL 内的条目直接返回，且命中计数增加。
func TestExpandCacheHitReusesResults(t *testing.T) {
	a := &App{}
	opts := expandOpts(expand.SourceWordlist)
	a.expandCachePut("example.com", opts, resolvedResults())

	got, ok := a.expandCacheGet("example.com", opts, 12)
	if !ok {
		t.Fatal("TTL 内应命中缓存")
	}
	if len(got) != len(resolvedResults()) {
		t.Fatalf("缓存结果数量不符：期望 %d，实际 %d", len(resolvedResults()), len(got))
	}
	if a.expandHits.Load() != 1 || a.expandMisses.Load() != 0 {
		t.Fatalf("命中计数不符：hits=%d misses=%d", a.expandHits.Load(), a.expandMisses.Load())
	}
}

// TTL 过期：savedAt 早于 TTL 的条目视为 miss。
func TestExpandCacheExpiredIsMiss(t *testing.T) {
	a := &App{}
	opts := expandOpts(expand.SourceWordlist)
	a.expandCachePut("example.com", opts, resolvedResults())
	// 直接把时间戳拨到 25 小时前，超过默认 12 小时 TTL。
	a.expandCacheMu.Lock()
	e := a.expandCache["example.com"]
	e.savedAt = time.Now().Add(-25 * time.Hour)
	a.expandCache["example.com"] = e
	a.expandCacheMu.Unlock()

	if _, ok := a.expandCacheGet("example.com", opts, 12); ok {
		t.Fatal("超过 TTL 的缓存不应命中")
	}
	if a.expandMisses.Load() != 1 {
		t.Fatalf("过期应计一次 miss，实际 %d", a.expandMisses.Load())
	}
}

// 指纹不符：展开参数变化（如来源/上限）应让旧缓存失效。
func TestExpandCacheFingerprintMismatch(t *testing.T) {
	a := &App{}
	a.expandCachePut("example.com", expandOpts(expand.SourceWordlist), resolvedResults())

	// 换一个来源组合，指纹不同。
	if _, ok := a.expandCacheGet("example.com", expandOpts(expand.SourceRules), 12); ok {
		t.Fatal("展开参数变化后不应命中旧缓存")
	}
}

// 手动刷新失效：forceRefresh 前清掉该域名缓存，随后取用为 miss。
func TestExpandCacheEvictOnForceRefresh(t *testing.T) {
	a := &App{}
	opts := expandOpts(expand.SourceWordlist)
	a.expandCachePut("example.com", opts, resolvedResults())

	a.expandCacheEvict("example.com")
	if _, ok := a.expandCacheGet("example.com", opts, 12); ok {
		t.Fatal("删除缓存后不应命中")
	}
}

// buildSubTargets：只保留可解析且有 IP 的子域名，并补齐探测基础参数。
func TestBuildSubTargetsFiltersUnresolved(t *testing.T) {
	base := config.Target{Name: "example.com", Port: 443, SNI: "example.com", Expand: true}
	subs := buildSubTargets(base, resolvedResults())

	if len(subs) != 2 {
		t.Fatalf("应过滤掉未解析/空 IP 的条目，期望 2 个，实际 %d 个", len(subs))
	}
	byName := map[string]config.Target{}
	for _, s := range subs {
		byName[s.Name] = s
		if s.Expand {
			t.Errorf("%s 应关闭子级展开", s.Name)
		}
		if s.SNI != s.Name {
			t.Errorf("%s 的 SNI 应等于自身名，实际 %s", s.Name, s.SNI)
		}
		if s.Port != 443 {
			t.Errorf("%s 应继承基础端口 443，实际 %d", s.Name, s.Port)
		}
		if len(s.Candidates) == 0 {
			t.Errorf("%s 应有候选 IP", s.Name)
		}
	}
	if byName["api.example.com"].Candidates == nil {
		t.Error("api.example.com 候选应非空")
	}
	if len(byName["api.example.com"].Candidates) != 2 {
		t.Errorf("api.example.com 应有 2 个候选，实际 %d", len(byName["api.example.com"].Candidates))
	}
}

// 展开配置非法时不写缓存（失败不缓存的一种情形）。
func TestExpandSubdomainsInvalidSourceNotCached(t *testing.T) {
	a := &App{}
	t0 := config.Target{Name: "example.com", Expand: true, ExpandSources: []string{"bogus"}}
	d := config.Defaults{ExpandCacheTTLHours: 12}

	got := a.expandSubdomains(context.Background(), t0, d, false)
	if got != nil {
		t.Fatalf("非法来源应返回 nil，实际 %v", got)
	}
	if len(a.expandCache) != 0 {
		t.Fatal("失败不应写入缓存")
	}
}

// 后台清扫：不在配置中与超过 TTL 的条目被删除，配置内的保留。
func TestSweepExpandCache(t *testing.T) {
	a := &App{}
	opts := expandOpts(expand.SourceWordlist)
	a.expandCachePut("keep.com", opts, resolvedResults())
	a.expandCachePut("gone.com", opts, resolvedResults())
	a.expandCachePut("expired.com", opts, resolvedResults())
	// 把过期条目的时间拨到 TTL 之外。
	a.expandCacheMu.Lock()
	e := a.expandCache["expired.com"]
	e.savedAt = time.Now().Add(-25 * time.Hour)
	a.expandCache["expired.com"] = e
	a.expandCacheMu.Unlock()

	a.sweepExpandCache(map[string]bool{"keep.com": true}, 12)

	if _, ok := a.expandCache["keep.com"]; !ok {
		t.Fatal("配置内条目应保留")
	}
	if _, ok := a.expandCache["gone.com"]; ok {
		t.Fatal("不在配置中的条目应被清扫")
	}
	if _, ok := a.expandCache["expired.com"]; ok {
		t.Fatal("超过 TTL 的条目应被清扫")
	}
	if a.expandCacheSize.Load() != 1 {
		t.Fatalf("缓存规模应为 1，实际 %d", a.expandCacheSize.Load())
	}
}

// 配置写路径即时回收：不在新配置中的条目立即消失。
func TestEvictExpandCacheExcept(t *testing.T) {
	a := &App{}
	opts := expandOpts(expand.SourceWordlist)
	a.expandCachePut("keep.com", opts, resolvedResults())
	a.expandCachePut("gone.com", opts, resolvedResults())

	a.evictExpandCacheExcept(map[string]bool{"keep.com": true})

	if _, ok := a.expandCache["keep.com"]; !ok {
		t.Fatal("keep 集合内条目应保留")
	}
	if _, ok := a.expandCache["gone.com"]; ok {
		t.Fatal("不在 keep 集合的条目应被回收")
	}
}

// parsedDomainSet 同时收录原文与小写键，大小写混写不误判。
func TestParsedDomainSetCaseInsensitive(t *testing.T) {
	set := parsedDomainSet([]config.Domain{{Name: "GitHub.com"}, {Name: " "}, {Name: "a.com"}})
	for _, key := range []string{"GitHub.com", "github.com", "a.com"} {
		if !set[key] {
			t.Fatalf("集合应含 %q", key)
		}
	}
	if set[""] {
		t.Fatal("空域名不应入集合")
	}
}
