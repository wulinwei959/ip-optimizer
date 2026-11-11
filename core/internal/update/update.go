// Package update 检查 GitHub 是否发布了新版本，供 /healthz 与界面提示。
// 只读 api.github.com 的 releases/latest，失败静默、不影响主流程。
package update

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// repo 是检查新版本的 GitHub 仓库（与 manifest 的 maintainer_url 一致）。
const repo = "wulinwei959/ip-optimizer"

// checkTimeout 是单次版本检查的 HTTP 超时。
const checkTimeout = 10 * time.Second

// recheckInterval 是版本复检周期。
const recheckInterval = time.Hour

// Compare 比较两个语义化版本（可带 v 前缀）。返回 -1/0/1 表示 a<b / a==b / a>b。
// 只比较 major.minor.patch 三段；预发布/构建元数据后缀被忽略（GitHub releases/latest
// 只返回正式版，故无需处理预发布排序）。非数字段按 0 处理。
func Compare(a, b string) int {
	pa, pb := parseVersion(a), parseVersion(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parseVersion 解析 vMAJOR.MINOR.PATCH 为三段整数，容忍 v 前缀与 -/+ 后缀。
func parseVersion(v string) [3]int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	var out [3]int
	for i := 0; i < 3 && i < len(parts); i++ {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			out[i] = n
		}
	}
	return out
}

// Checker 周期性检查 GitHub 新版本并缓存结果。所有公开方法并发安全。
type Checker struct {
	mu        sync.RWMutex
	current   string
	latest    string
	available bool
	checkedAt time.Time
	enabled   bool
	client    *http.Client
}

// New 创建检查器。HO_UPDATE_CHECK=off 时禁用（所有方法 no-op）。
func New(current string) *Checker {
	enabled := strings.ToLower(strings.TrimSpace(os.Getenv("HO_UPDATE_CHECK"))) != "off"
	return &Checker{
		current: current,
		enabled: enabled,
		client:  &http.Client{Timeout: checkTimeout},
	}
}

// Check 查询一次最新版本并更新缓存。任何失败都静默保留上次结果。
func (c *Checker) Check(ctx context.Context) {
	if c == nil || !c.enabled {
		return
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "hosts-optimizer/"+c.current)
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return
	}
	latest := strings.TrimSpace(rel.TagName)
	if latest == "" {
		return
	}
	c.mu.Lock()
	c.latest = latest
	c.available = Compare(latest, c.current) > 0
	c.checkedAt = time.Now()
	c.mu.Unlock()
}

// Run 启动后立即查一次，随后每小时复检，直到 ctx 取消。禁用时直接返回。
func (c *Checker) Run(ctx context.Context) {
	if c == nil || !c.enabled {
		return
	}
	c.Check(ctx)
	ticker := time.NewTicker(recheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Check(ctx)
		}
	}
}

// Status 返回最新版本、是否有更新、最近检查时间（供 /healthz）。
func (c *Checker) Status() (latest string, available bool, checkedAt time.Time) {
	if c == nil {
		return "", false, time.Time{}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latest, c.available, c.checkedAt
}
