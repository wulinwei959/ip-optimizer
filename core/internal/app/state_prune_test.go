package app

import (
	"testing"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/store"
)

// 修剪按配置域名集合删除状态，键归一避免大小写混写误删。
func TestPruneStateDomains(t *testing.T) {
	a := &App{state: &store.State{Domains: map[string]*store.DomainState{
		"keep.com":   {},
		"GitHub.com": {}, // 配置原文大小写，归一后应保留
		"gone.com":   {},
		"removed.com": {},
	}}}

	a.pruneStateDomains(parsedDomainSet([]config.Domain{{Name: "keep.com"}, {Name: "GitHub.com"}}))

	if _, ok := a.state.Domains["keep.com"]; !ok {
		t.Fatal("配置内域名状态应保留")
	}
	if _, ok := a.state.Domains["GitHub.com"]; !ok {
		t.Fatal("大小写混写的配置内域名不应被误删")
	}
	if _, ok := a.state.Domains["gone.com"]; ok {
		t.Fatal("配置外域名状态应被删除")
	}
	if _, ok := a.state.Domains["removed.com"]; ok {
		t.Fatal("配置外域名状态应被删除")
	}
	if a.stateDomainsSize.Load() != 2 {
		t.Fatalf("修剪后规模应为 2，实际 %d", a.stateDomainsSize.Load())
	}
}
