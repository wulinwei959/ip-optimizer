// Package expand 域名展开：从主域名发现相关子域名
package expand

import (
	"context"
	"testing"
	"time"
)

func TestExpandWordlist(t *testing.T) {
	exp := New(Options{
		Sources:       []Source{SourceWordlist},
		Concurrency:   5,
		Timeout:       5 * time.Second,
		MaxSubdomains: 10,
		ProbeDNS:      []string{"223.5.5.5"},
		AllowPrivate:  false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := exp.Expand(ctx, "example.com")
	if err != nil {
		t.Fatalf("Expand 失败: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("未发现任何子域名")
	}

	// 验证所有结果都是 example.com 的子域名
	for _, r := range results {
		if r.Domain == "example.com" {
			continue // 允许根域名
		}
		if !hasSuffix(r.Domain, ".example.com") {
			t.Errorf("非预期域名: %s", r.Domain)
		}
		if r.Source != SourceWordlist {
			t.Errorf("来源不匹配: 期望 wordlist，实际 %s", r.Source)
		}
	}

	t.Logf("发现 %d 个子域名", len(results))
}

func TestExpandRules(t *testing.T) {
	exp := New(Options{
		Sources:       []Source{SourceRules},
		Concurrency:   5,
		Timeout:       5 * time.Second,
		MaxSubdomains: 10,
		ProbeDNS:      []string{"223.5.5.5"},
		AllowPrivate:  false,
		KnownRules: map[string][]string{
			"github.com": {"api", "raw"}, // 传入前缀，applyRules 会自动拼接 .github.com
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := exp.Expand(ctx, "github.com")
	if err != nil {
		t.Fatalf("Expand 失败: %v", err)
	}

	found := make(map[string]bool)
	for _, r := range results {
		found[r.Domain] = true
		if r.Source != SourceRules {
			t.Errorf("来源不匹配: 期望 rules，实际 %s", r.Source)
		}
	}

	// 验证内置规则生效
	if !found["api.github.com"] {
		t.Error("未发现 api.github.com")
	}
	if !found["raw.github.com"] {
		t.Error("未发现 raw.github.com")
	}

	t.Logf("发现 %d 个子域名", len(results))
}

func TestExpandMaxSubdomains(t *testing.T) {
	exp := New(Options{
		Sources:       []Source{SourceWordlist},
		Concurrency:   5,
		Timeout:       5 * time.Second,
		MaxSubdomains: 3, // 限制为 3 个
		ProbeDNS:      []string{"223.5.5.5"},
		AllowPrivate:  false,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := exp.Expand(ctx, "example.com")
	if err != nil {
		t.Fatalf("Expand 失败: %v", err)
	}

	if len(results) > 3 {
		t.Errorf("结果数量 %d 超过限制 3", len(results))
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}