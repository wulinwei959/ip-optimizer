package app

import (
	"testing"

	"hosts-optimizer/internal/config"
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
