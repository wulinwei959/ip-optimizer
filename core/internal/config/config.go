// Package config 读取 domains.json 并合并 HO_* 环境变量。
// 无第三方依赖：只用 encoding/json 解析配置。
package config

import (
	"encoding/json"
	"fmt"
	"log"
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
	AllowPrivate  bool     `json:"allow_private"`
	Expand        bool     `json:"expand"`
	ExpandSources []string `json:"expand_sources"`
	Disabled      bool     `json:"disabled"`
}

// Defaults 是全局默认值，可被单个域名覆盖。
type Defaults struct {
	ScheduleMinutes        int       `json:"schedule_minutes"`
	ProbeDNS               []string  `json:"probe_dns"`
	ProbePort              int       `json:"probe_port"`
	Concurrency            int       `json:"concurrency"`
	HysteresisPercent      int       `json:"hysteresis_percent"`
	HysteresisRounds       int       `json:"hysteresis_rounds"`
	ExpectStatus           []int     `json:"expect_status"`
	MaxCandidates          int       `json:"max_candidates"`
	TCPRounds              int       `json:"tcp_rounds"`
	TimeoutSeconds         int       `json:"timeout_seconds"`
	ProbeTopN              int       `json:"probe_top_n"`
	ProbeFullEvery         int       `json:"probe_full_every"`
	WatchIntervalSeconds   int       `json:"watch_interval_seconds"`
	WatchSwitchPercent     int       `json:"watch_switch_percent"`
	ExpandConcurrency      int       `json:"expand_concurrency"`
	ExpandTimeoutSeconds   int       `json:"expand_timeout_seconds"`
	ExpandMaxSubdomains    int       `json:"expand_max_subdomains"`
	ExpandSources          []string  `json:"expand_sources"`
	ExpandCacheTTLHours    int       `json:"expand_cache_ttl_hours"`
	HistoryRetentionMonths int       `json:"history_retention_months"`
	DNS                    DNSConfig `json:"dns"`
}

// DNSConfig 控制内置 DNS 应答器（供 AdGuard Home 上游分流）。
type DNSConfig struct {
	Listen string `json:"listen"` // UDP 监听地址 host:port；空字符串表示禁用
	TTL    int    `json:"ttl"`    // A 记录缓存秒数，决定 IP 切换的收敛上限
}

// Runtime 是一轮探测所需的全部运行时信息。
type Runtime struct {
	Config    Config
	ConfigDir string
	OutputDir string
	StateDir  string
	DataDir   string
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
// 主路径缺失而旧路径（HO_LEGACY_CONFIG）存在时，一次性把旧配置迁移到主路径。
func Load() (*Runtime, error) {
	cfgDir := envOr("HO_CONFIG", ".")
	path := filepath.Join(cfgDir, "domains.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if migrated, ok := migrateFromLegacy(cfgDir, path); ok {
			data = migrated
		} else {
			return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
		}
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
		DataDir:   envOr("HO_DATA", ""),
		Port:      envOr("HO_PORT", "8088"),
		TZ:        envOr("HO_TZ", "Asia/Shanghai"),
		CABundle:  envOr("HO_CA_BUNDLE", ""),
	}, nil
}

// migrateFromLegacy 处理 domains.json 从旧位置到主位置的一次性迁移：
// 读取旧文件、原子写回主路径、删除旧文件（完成「移动」），返回旧文件内容供本轮继续使用。
// 无旧文件可迁移或迁移失败时返回 false，调用方沿用主路径缺失的原始错误。
func migrateFromLegacy(cfgDir, mainPath string) ([]byte, bool) {
	legacyDir := strings.TrimSpace(os.Getenv("HO_LEGACY_CONFIG"))
	if legacyDir == "" {
		return nil, false
	}
	legacyPath := filepath.Join(legacyDir, "domains.json")
	if legacyPath == mainPath {
		return nil, false
	}
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return nil, false
	}
	// 原子写回主路径：先写临时文件再 rename，避免半写状态被读到。
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		log.Printf("配置迁移：创建目录 %s 失败: %v", cfgDir, err)
		return nil, false
	}
	tmp := mainPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		log.Printf("配置迁移：写临时文件失败: %v", err)
		return nil, false
	}
	if err := os.Rename(tmp, mainPath); err != nil {
		log.Printf("配置迁移：写回主路径失败: %v", err)
		return nil, false
	}
	// 主路径已就位，删除旧文件完成移动；删除失败只记日志，不影响本轮读取。
	if err := os.Remove(legacyPath); err != nil {
		log.Printf("配置迁移后删除旧文件失败（可忽略）: %v", err)
	}
	log.Printf("配置已迁移：%s → %s", legacyPath, mainPath)
	return data, true
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
	// 自适应探测面：常规轮次只测「当前 IP + 前 N 个挑战者」，每 K 轮做一次全量扫描。
	if d.ProbeTopN <= 0 {
		d.ProbeTopN = 5
	}
	if d.ProbeFullEvery <= 0 {
		d.ProbeFullEvery = 6
	}
	// 健康探针：每隔若干秒只测一次当前 IP，失效或明显变慢时立即触发一次小轮次。
	// 阈值取 100%：健康探针比的是「当前 IP 自己上一轮的时延」，而相邻两次测量之间
	// 网络抖动就可能超过 20%，阈值太紧会把每个探测周期都误判成变慢、白跑一轮。
	if d.WatchIntervalSeconds == 0 {
		d.WatchIntervalSeconds = 60
	}
	if d.WatchSwitchPercent == 0 {
		d.WatchSwitchPercent = 100
	}
	if d.TimeoutSeconds <= 0 {
		d.TimeoutSeconds = 3
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
	if d.ExpandCacheTTLHours <= 0 {
		d.ExpandCacheTTLHours = 12
	}
	if d.HistoryRetentionMonths <= 0 {
		d.HistoryRetentionMonths = 12
	}
	// DNS 应答器默认值：绑定本机回环 + 高端口，与 AdGuard Home 同机部署。
	// off / disabled / none / 0 / false 归一化为空字符串表示禁用。
	switch strings.ToLower(strings.TrimSpace(d.DNS.Listen)) {
	case "":
		d.DNS.Listen = "127.0.0.1:18053"
	case "off", "disabled", "none", "0", "false":
		d.DNS.Listen = ""
	}
	if d.DNS.TTL <= 0 {
		d.DNS.TTL = 60
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
		{"HO_DNS_TTL", &d.DNS.TTL},
		{"HO_PROBE_TOP_N", &d.ProbeTopN},
		{"HO_PROBE_FULL_EVERY", &d.ProbeFullEvery},
		{"HO_WATCH_INTERVAL_SECONDS", &d.WatchIntervalSeconds},
		{"HO_WATCH_SWITCH_PERCENT", &d.WatchSwitchPercent},
		{"HO_EXPAND_CACHE_TTL_HOURS", &d.ExpandCacheTTLHours},
	} {
		if err := envInt(item.key, item.dst); err != nil {
			return err
		}
	}
	// DNS 应答器监听地址支持 off 类词表禁用，语义与配置字段一致。
	if v := strings.TrimSpace(os.Getenv("HO_DNS_LISTEN")); v != "" {
		switch strings.ToLower(v) {
		case "off", "disabled", "none", "0", "false":
			d.DNS.Listen = ""
		default:
			d.DNS.Listen = v
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
	if d.ProbeTopN < 1 || d.ProbeTopN > 64 {
		return fmt.Errorf("probe_top_n 必须在 1..64，当前 %d", d.ProbeTopN)
	}
	if d.ProbeFullEvery < 1 || d.ProbeFullEvery > 1000 {
		return fmt.Errorf("probe_full_every 必须在 1..1000，当前 %d", d.ProbeFullEvery)
	}
	if d.WatchIntervalSeconds < 5 || d.WatchIntervalSeconds > 3600 {
		return fmt.Errorf("watch_interval_seconds 必须在 5..3600，当前 %d", d.WatchIntervalSeconds)
	}
	if d.WatchSwitchPercent < 1 || d.WatchSwitchPercent > 100 {
		return fmt.Errorf("watch_switch_percent 必须在 1..100，当前 %d", d.WatchSwitchPercent)
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
	if d.ExpandCacheTTLHours < 1 || d.ExpandCacheTTLHours > 240 {
		return fmt.Errorf("expand_cache_ttl_hours 必须在 1..240，当前 %d", d.ExpandCacheTTLHours)
	}
	if d.HistoryRetentionMonths < 1 || d.HistoryRetentionMonths > 120 {
		return fmt.Errorf("history_retention_months 必须在 1..120，当前 %d", d.HistoryRetentionMonths)
	}
	// DNS 应答器校验：TTL 决定切换收敛上限，过小会让 AGH 频繁回源，过大则失去意义。
	if d.DNS.TTL < 5 || d.DNS.TTL > 3600 {
		return fmt.Errorf("dns.ttl 必须在 5..3600，当前 %d", d.DNS.TTL)
	}
	if d.DNS.Listen != "" {
		host, portStr, err := net.SplitHostPort(d.DNS.Listen)
		if err != nil {
			return fmt.Errorf("dns.listen 必须是 host:port 形式（如 127.0.0.1:18053），当前 %q", d.DNS.Listen)
		}
		if host != "" && net.ParseIP(host) == nil {
			return fmt.Errorf("dns.listen 的 host 必须是 IP 字面量（空 = 全接口），当前 %q", host)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("dns.listen 的端口必须在 1..65535，当前 %q", portStr)
		}
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
	// 域名级展开配置覆盖全局默认
	if d.Expand {
		if len(d.ExpandSources) > 0 {
			t.ExpandSources = append([]string(nil), d.ExpandSources...)
		}
	}
	t.Disabled = d.Disabled
	return t
}
