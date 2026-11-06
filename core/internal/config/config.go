// Package config 读取 domains.json 并合并 HO_* 环境变量。
// 无第三方依赖：只用 encoding/json 解析配置。
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"hosts-optimizer/internal/dnsquery"
)

// Config 是 domains.json 的完整结构。
type Config struct {
	Domains  []Domain `json:"domains"`
	Defaults Defaults `json:"defaults"`
}

// Domain 描述一个待优选的域名。
type Domain struct {
	Name          string   `json:"name"`
	SNI           string   `json:"sni"`
	Port          int      `json:"port"`
	Candidates    []string `json:"candidates"`
	ExpectStatus  []int    `json:"expect_status"`
	SuppressAAAA  *bool    `json:"suppress_aaaa"`
	AllowPrivate  bool     `json:"allow_private"`
	Expand        bool     `json:"expand"`
	ExpandSources []string `json:"expand_sources"`
	Disabled      bool     `json:"disabled"`
}

// Defaults 是全局默认值，可被单个域名覆盖。
type Defaults struct {
	ScheduleMinutes        int      `json:"schedule_minutes"`
	ProbeDNS               []string `json:"probe_dns"`
	ProbePort              int      `json:"probe_port"`
	Concurrency            int      `json:"concurrency"`
	HysteresisPercent      int      `json:"hysteresis_percent"`
	HysteresisRounds       int      `json:"hysteresis_rounds"`
	ExpectStatus           []int    `json:"expect_status"`
	Outputs                []string `json:"outputs"`
	MaxCandidates          int      `json:"max_candidates"`
	TCPRounds              int      `json:"tcp_rounds"`
	TimeoutSeconds         int      `json:"timeout_seconds"`
	ExpandConcurrency      int      `json:"expand_concurrency"`
	ExpandTimeoutSeconds   int      `json:"expand_timeout_seconds"`
	ExpandMaxSubdomains    int      `json:"expand_max_subdomains"`
	ExpandSources          []string `json:"expand_sources"`
	HistoryRetentionMonths int      `json:"history_retention_months"`
}

// Runtime 是一轮探测所需的全部运行时信息。
type Runtime struct {
	Config    Config
	ConfigDir string
	OutputDir string
	StateDir  string
	Port      string
	TZ        string
	CABundle  string
}

// Target 是把 Domain 与 Defaults 合并后的最终参数。
type Target struct {
	Name                string
	SNI                 string
	Port                int
	Candidates          []string
	ExpectStatus        []int
	SuppressAAAA        bool
	AllowPrivate        bool
	Expand              bool
	ExpandSources       []string
	ExpandConcurrency   int
	ExpandTimeout       int
	ExpandMaxSubdomains int
	Disabled            bool
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, dst *int) error {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("环境变量 %s 不是整数: %w", key, err)
	}
	*dst = n
	return nil
}

// Parse 解析并验证配置 JSON，仅用于 API 校验。
func Parse(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	// 与运行时 Load 保持一致：缺省字段先补默认值再校验，避免可选字段缺失被误判为非法。
	applyDefaults(&c)
	if err := validate(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Load 每次调用都重新读取 domains.json，因此编辑域名清单后下一轮自动生效，无需重启。
func Load() (*Runtime, error) {
	cfgDir := envOr("HO_CONFIG", ".")
	path := filepath.Join(cfgDir, "domains.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("解析 %s 失败: %w", path, err)
	}
	applyDefaults(&c)
	if err := applyEnv(&c); err != nil {
		return nil, err
	}
	if err := validate(&c); err != nil {
		return nil, err
	}
	return &Runtime{
		Config:    c,
		ConfigDir: cfgDir,
		OutputDir: envOr("HO_OUTPUT", "./output"),
		StateDir:  envOr("HO_STATE", "./state"),
		Port:      envOr("HO_PORT", "8088"),
		TZ:        envOr("HO_TZ", "Asia/Shanghai"),
		CABundle:  envOr("HO_CA_BUNDLE", ""),
	}, nil
}

func applyDefaults(c *Config) {
	d := &c.Defaults
	if d.ScheduleMinutes <= 0 {
		d.ScheduleMinutes = 60
	}
	if len(d.ProbeDNS) == 0 {
		d.ProbeDNS = []string{"223.5.5.5", "119.29.29.29"}
	}
	if d.ProbePort <= 0 {
		d.ProbePort = 443
	}
	if d.Concurrency <= 0 {
		d.Concurrency = 20
	}
	if d.HysteresisPercent < 0 {
		d.HysteresisPercent = 0
	}
	if d.HysteresisRounds <= 0 {
		d.HysteresisRounds = 2
	}
	if d.MaxCandidates <= 0 {
		d.MaxCandidates = 64
	}
	if d.TCPRounds <= 0 {
		d.TCPRounds = 3
	}
	if d.TimeoutSeconds <= 0 {
		d.TimeoutSeconds = 3
	}
	if len(d.Outputs) == 0 {
		d.Outputs = []string{"hosts.txt", "agh.txt", "status.json"}
	}
	// 展开功能默认值
	if d.ExpandConcurrency <= 0 {
		d.ExpandConcurrency = 10
	}
	if d.ExpandTimeoutSeconds <= 0 {
		d.ExpandTimeoutSeconds = 10
	}
	if d.ExpandMaxSubdomains <= 0 {
		d.ExpandMaxSubdomains = 50
	}
	if len(d.ExpandSources) == 0 {
		d.ExpandSources = []string{"wordlist", "rules"}
	}
	if d.HistoryRetentionMonths <= 0 {
		d.HistoryRetentionMonths = 12
	}
}

func applyEnv(c *Config) error {
	d := &c.Defaults
	for _, item := range []struct {
		key string
		dst *int
	}{
		{"HO_SCHEDULE_MINUTES", &d.ScheduleMinutes},
		{"HO_PROBE_CONCURRENCY", &d.Concurrency},
	} {
		if err := envInt(item.key, item.dst); err != nil {
			return err
		}
	}
	if v := strings.TrimSpace(os.Getenv("HO_PROBE_DNS")); v != "" {
		var servers []string
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				servers = append(servers, s)
			}
		}
		if len(servers) > 0 {
			d.ProbeDNS = servers
		}
	}
	return nil
}

func validate(c *Config) error {
	d := c.Defaults
	if d.ScheduleMinutes < 1 || d.ScheduleMinutes > 1440 {
		return fmt.Errorf("schedule_minutes 必须在 1..1440，当前 %d", d.ScheduleMinutes)
	}
	if d.Concurrency < 1 || d.Concurrency > 256 {
		return fmt.Errorf("concurrency 必须在 1..256，当前 %d", d.Concurrency)
	}
	if d.HysteresisPercent < 0 || d.HysteresisPercent > 100 {
		return fmt.Errorf("hysteresis_percent 必须在 0..100，当前 %d", d.HysteresisPercent)
	}
	if d.HysteresisRounds < 1 || d.HysteresisRounds > 100 {
		return fmt.Errorf("hysteresis_rounds 必须在 1..100，当前 %d", d.HysteresisRounds)
	}
	if d.ProbePort < 1 || d.ProbePort > 65535 {
		return fmt.Errorf("probe_port 非法: %d", d.ProbePort)
	}
	if d.TimeoutSeconds < 1 || d.TimeoutSeconds > 60 {
		return fmt.Errorf("timeout_seconds 必须在 1..60，当前 %d", d.TimeoutSeconds)
	}
	// 验证展开相关配置
	if d.ExpandConcurrency < 1 || d.ExpandConcurrency > 256 {
		return fmt.Errorf("expand_concurrency 必须在 1..256，当前 %d", d.ExpandConcurrency)
	}
	if d.ExpandTimeoutSeconds < 1 || d.ExpandTimeoutSeconds > 60 {
		return fmt.Errorf("expand_timeout_seconds 必须在 1..60，当前 %d", d.ExpandTimeoutSeconds)
	}
	if d.ExpandMaxSubdomains < 1 || d.ExpandMaxSubdomains > 1000 {
		return fmt.Errorf("expand_max_subdomains 必须在 1..1000，当前 %d", d.ExpandMaxSubdomains)
	}
	if d.HistoryRetentionMonths < 1 || d.HistoryRetentionMonths > 120 {
		return fmt.Errorf("history_retention_months 必须在 1..120，当前 %d", d.HistoryRetentionMonths)
	}
	validSources := map[string]bool{"ct": true, "wordlist": true, "rules": true}
	for _, s := range d.ExpandSources {
		if !validSources[s] {
			return fmt.Errorf("expand_sources 含非法值 %q，合法值: ct/wordlist/rules", s)
		}
	}
	for _, s := range d.ProbeDNS {
		// UDP 上游必须是字面 IP；DoT/DoH 允许主机名（由 TLS/HTTPS 校验证书）。
		if err := dnsquery.ValidateServer(s); err != nil {
			return fmt.Errorf("probe_dns 地址 %q 非法: %w", s, err)
		}
	}
	seen := make(map[string]bool)
	for _, dom := range c.Domains {
		name := strings.TrimSpace(dom.Name)
		if name == "" || strings.ContainsAny(name, " \t/") || strings.Contains(name, "://") {
			return fmt.Errorf("非法域名: %q", dom.Name)
		}
		if seen[name] {
			return fmt.Errorf("域名重复: %s", name)
		}
		seen[name] = true
		if dom.Port < 0 || dom.Port > 65535 {
			return fmt.Errorf("%s 的 port 非法: %d", name, dom.Port)
		}
		for _, ip := range dom.Candidates {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("%s 的 candidates 含非法 IP: %q", name, ip)
			}
		}
		// 验证域名级展开配置
		if dom.Expand {
			if len(dom.ExpandSources) > 0 {
				for _, s := range dom.ExpandSources {
					if !validSources[s] {
						return fmt.Errorf("%s 的 expand_sources 含非法值 %q，合法值: ct/wordlist/rules", name, s)
					}
				}
			}
		}
	}
	return nil
}

// Resolve 合并单个域名与全局默认值。
func (c *Config) Resolve(d Domain) Target {
	t := Target{
		Name:                strings.TrimSpace(d.Name),
		Candidates:          append([]string(nil), d.Candidates...),
		AllowPrivate:        d.AllowPrivate,
		SuppressAAAA:        true,
		ExpectStatus:        append([]int(nil), c.Defaults.ExpectStatus...),
		Port:                c.Defaults.ProbePort,
		SNI:                 strings.TrimSpace(d.SNI),
		Expand:              d.Expand,
		ExpandSources:       d.ExpandSources,
		ExpandConcurrency:   c.Defaults.ExpandConcurrency,
		ExpandTimeout:       c.Defaults.ExpandTimeoutSeconds,
		ExpandMaxSubdomains: c.Defaults.ExpandMaxSubdomains,
	}
	if t.SNI == "" {
		t.SNI = t.Name
	}
	if d.Port > 0 {
		t.Port = d.Port
	}
	if len(d.ExpectStatus) > 0 {
		t.ExpectStatus = append([]int(nil), d.ExpectStatus...)
	}
	if d.SuppressAAAA != nil {
		t.SuppressAAAA = *d.SuppressAAAA
	}
	// 域名级展开配置覆盖全局默认
	if d.Expand {
		if len(d.ExpandSources) > 0 {
			t.ExpandSources = append([]string(nil), d.ExpandSources...)
		}
	}
	t.Disabled = d.Disabled
	return t
}
