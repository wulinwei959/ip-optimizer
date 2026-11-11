// Package expand 域名展开：从主域名发现相关子域名
package expand

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"hosts-optimizer/internal/dnsquery"
)

// Source 展开来源
type Source string

const (
	SourceCT       Source = "ct"       // Certificate Transparency 日志
	SourceWordlist Source = "wordlist" // 常见子域名字典
	SourceRules    Source = "rules"    // 内置服务规则
)

// Result 展开结果
type Result struct {
	Domain   string   `json:"domain"`
	Source   Source   `json:"source"`
	Resolved bool     `json:"resolved"`
	IPs      []string `json:"ips,omitempty"`
}

// Options 展开选项
type Options struct {
	Sources       []Source
	Concurrency   int
	Timeout       time.Duration
	MaxSubdomains int
	ProbeDNS      []string
	AllowPrivate  bool
	KnownRules    map[string][]string // domain -> subdomains
}

// Expander 域名展开器
type Expander struct {
	opts Options
}

func New(opts Options) *Expander {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.MaxSubdomains <= 0 {
		opts.MaxSubdomains = 50
	}
	return &Expander{opts: opts}
}

// Expand 执行域名展开，返回发现的子域名列表
func (e *Expander) Expand(ctx context.Context, domain string) ([]Result, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("空域名")
	}

	var allCandidates []struct {
		Domain string
		Source Source
	}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 1. CT 日志查询
	if e.hasSource(SourceCT) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs := e.queryCT(ctx, domain)
			mu.Lock()
			for _, s := range subs {
				allCandidates = append(allCandidates, struct {
					Domain string
					Source Source
				}{Domain: s, Source: SourceCT})
			}
			mu.Unlock()
		}()
	}

	// 2. 常见子域名字典
	if e.hasSource(SourceWordlist) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs := e.generateWordlist(domain)
			mu.Lock()
			for _, s := range subs {
				allCandidates = append(allCandidates, struct {
					Domain string
					Source Source
				}{Domain: s, Source: SourceWordlist})
			}
			mu.Unlock()
		}()
	}

	// 3. 内置服务规则
	if e.hasSource(SourceRules) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subs := e.applyRules(domain)
			mu.Lock()
			for _, s := range subs {
				allCandidates = append(allCandidates, struct {
					Domain string
					Source Source
				}{Domain: s, Source: SourceRules})
			}
			mu.Unlock()
		}()
	}

	wg.Wait()

	// 去重（保留首次出现的来源）
	seen := make(map[string]bool)
	unique := make([]struct {
		Domain string
		Source Source
	}, 0, len(allCandidates))
	for _, c := range allCandidates {
		s := strings.TrimSpace(strings.ToLower(c.Domain))
		if s == "" || s == domain || strings.HasPrefix(s, ".") {
			continue
		}
		if !seen[s] {
			seen[s] = true
			unique = append(unique, struct {
				Domain string
				Source Source
			}{Domain: s, Source: c.Source})
		}
	}

	// 限制数量
	if len(unique) > e.opts.MaxSubdomains {
		unique = unique[:e.opts.MaxSubdomains]
	}

	// 并发 DNS 探测验证存活
	results := e.probeSubdomains(ctx, unique)
	return results, nil
}

func (e *Expander) hasSource(s Source) bool {
	for _, src := range e.opts.Sources {
		if src == s {
			return true
		}
	}
	return false
}

// crtClient 复用于所有 crt.sh 请求：连接与 TLS 会话可复用，避免每次展开都重新握手。
// 单次超时由请求的 context 控制（queryCT 里已带 WithTimeout）。
var crtClient = &http.Client{Transport: &http.Transport{
	Proxy:                 nil,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          16,
	MaxIdleConnsPerHost:   4,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   5 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
	DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
}}

// queryCT 查询 Certificate Transparency 日志 (crt.sh API)
func (e *Expander) queryCT(ctx context.Context, domain string) []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	ctx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return []string{}
	}
	req.Header.Set("User-Agent", "hosts-optimizer/1.0")

	resp, err := crtClient.Do(req)
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []string{}
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return []string{}
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || name == domain || strings.HasPrefix(name, "*.") || strings.HasPrefix(name, ".") {
				continue
			}
			// 只保留子域名
			if strings.HasSuffix(name, "."+domain) || name == domain {
				if !seen[name] {
					seen[name] = true
					subs = append(subs, name)
				}
			}
		}
	}
	return subs
}

// generateWordlist 从字典生成子域名
func (e *Expander) generateWordlist(domain string) []string {
	prefixes := []string{
		"www", "api", "cdn", "assets", "static", "img", "image", "images",
		"media", "files", "download", "dl", "up", "upload",
		"app", "apps", "web", "admin", "manage", "console", "dashboard",
		"dev", "test", "staging", "stage", "pre", "prod", "production",
		"v1", "v2", "v3", "api-v1", "api-v2", "api-v3",
		"gateway", "gate", "proxy", "edge",
		"auth", "login", "sso", "oauth", "oidc",
		"shop", "store", "pay", "payment", "billing",
		"blog", "docs", "doc", "help", "support", "kb", "knowledge",
		"status", "monitor", "metrics", "health", "ping",
		"ws", "wss", "socket", "realtime", "push",
		"mail", "email", "smtp", "imap", "pop",
		"git", "gitlab", "github", "svn", "hg",
		"jenkins", "ci", "cd", "build", "deploy",
		"registry", "docker", "harbor", "npm", "maven",
		"db", "database", "sql", "redis", "mongo", "es", "elasticsearch",
		"mq", "rabbitmq", "kafka", "nsq", "pulsar",
		"log", "logs", "logging", "trace", "jaeger", "zipkin",
		"grafana", "prometheus", "alertmanager",
		"vpn", "ssh", "rdp", "ftp", "sftp",
		"backup", "bak", "archive",
		"cdn1", "cdn2", "cdn3", "edge1", "edge2",
		"us", "eu", "ap", "cn", "hk", "sg", "jp", "kr",
		"sh", "bj", "gz", "sz", "hk",
	}

	var subs []string
	for _, p := range prefixes {
		subs = append(subs, p+"."+domain)
	}
	return subs
}

// applyRules 应用内置服务规则。
// 规则值既可以是完整主机名（如 raw.githubusercontent.com），
// 也可以是单段标签（如 api），后者会拼接到当前域名下。
func (e *Expander) applyRules(domain string) []string {
	rules := e.opts.KnownRules
	if rules == nil {
		rules = defaultKnownRules()
	}

	var subs []string
	seen := make(map[string]bool)
	for root, entries := range rules {
		root = strings.ToLower(strings.TrimSpace(root))
		if root == "" || (domain != root && !strings.HasSuffix(domain, "."+root)) {
			continue
		}
		for _, entry := range entries {
			entry = strings.ToLower(strings.TrimSpace(entry))
			if entry == "" {
				continue
			}
			candidate := entry
			if !strings.Contains(entry, ".") {
				candidate = entry + "." + domain
			}
			if candidate == domain || seen[candidate] {
				continue
			}
			seen[candidate] = true
			subs = append(subs, candidate)
		}
	}
	sort.Strings(subs)
	return subs
}

// defaultKnownRules 内置已知服务的子域名规则
func defaultKnownRules() map[string][]string {
	return map[string][]string{
		"github.com": {
			"api.github.com",
			"gist.github.com",
			"assets.github.com",
			"collector.github.com",
			"github.githubassets.com",
			"raw.githubusercontent.com",
			"gist.githubusercontent.com",
			"avatars.githubusercontent.com",
			"camo.githubusercontent.com",
			"user-images.githubusercontent.com",
			"objects.githubusercontent.com",
		},
		"gitlab.com": {
			"registry.gitlab.com",
			"packages.gitlab.com",
		},
		"googleapis.com": {
			"www.googleapis.com",
			"oauth2.googleapis.com",
			"content.googleapis.com",
			"storage.googleapis.com",
			"cloudresourcemanager.googleapis.com",
		},
		"cloudflare.com": {
			"api.cloudflare.com",
			"dash.cloudflare.com",
			"workers.cloudflare.com",
		},
		"docker.io": {
			"registry-1.docker.io",
			"auth.docker.io",
			"index.docker.io",
		},
		"githubusercontent.com": {
			"raw.githubusercontent.com",
			"gist.githubusercontent.com",
			"user-images.githubusercontent.com",
			"avatars.githubusercontent.com",
			"camo.githubusercontent.com",
			"objects.githubusercontent.com",
		},
	}
}

// probeSubdomains 并发探测子域名是否可解析
func (e *Expander) probeSubdomains(ctx context.Context, subdomains []struct {
	Domain string
	Source Source
}) []Result {
	sem := make(chan struct{}, e.opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]Result, 0, len(subdomains))

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string, src Source) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			ctxSub, cancel := context.WithTimeout(ctx, e.opts.Timeout)
			defer cancel()

			ips, err := dnsquery.Collect(ctxSub, subdomain, e.opts.ProbeDNS, e.opts.Timeout, e.opts.AllowPrivate, 5)
			resolved := err == nil && len(ips) > 0

			mu.Lock()
			results = append(results, Result{
				Domain:   subdomain,
				Source:   src,
				Resolved: resolved,
				IPs:      ips,
			})
			mu.Unlock()
		}(sub.Domain, sub.Source)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Resolved != results[j].Resolved {
			return results[i].Resolved
		}
		return results[i].Domain < results[j].Domain
	})

	return results
}
