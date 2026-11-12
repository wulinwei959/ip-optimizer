package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestDNSDefaults 验证 DNS 应答器的默认值：本机回环 + 高端口，TTL 60 秒。
func TestDNSDefaults(t *testing.T) {
	c := Config{}
	applyDefaults(&c)
	if c.Defaults.DNS.Listen != "127.0.0.1:18053" {
		t.Fatalf("默认 listen 应为 127.0.0.1:18053，实际 %q", c.Defaults.DNS.Listen)
	}
	if c.Defaults.DNS.TTL != 60 {
		t.Fatalf("默认 ttl 应为 60，实际 %d", c.Defaults.DNS.TTL)
	}
}

// TestDNSListenOffWords 验证 off 类词表被归一化为空字符串（禁用）。
func TestDNSListenOffWords(t *testing.T) {
	for _, word := range []string{"off", "OFF", " disabled ", "None", "0", "false"} {
		c := Config{Defaults: Defaults{DNS: DNSConfig{Listen: word}}}
		applyDefaults(&c)
		if c.Defaults.DNS.Listen != "" {
			t.Fatalf("词表 %q 应被归一化为禁用（空串），实际 %q", word, c.Defaults.DNS.Listen)
		}
	}
	// 非 off 类词表应原样保留。
	c := Config{Defaults: Defaults{DNS: DNSConfig{Listen: "0.0.0.0:5353"}}}
	applyDefaults(&c)
	if c.Defaults.DNS.Listen != "0.0.0.0:5353" {
		t.Fatalf("自定义地址应保留，实际 %q", c.Defaults.DNS.Listen)
	}
}

// TestDNSEnvOverride 验证 HO_DNS_LISTEN 与 HO_DNS_TTL 环境变量覆盖。
func TestDNSEnvOverride(t *testing.T) {
	t.Setenv("HO_DNS_LISTEN", "127.0.0.1:15353")
	t.Setenv("HO_DNS_TTL", "15")
	c := Config{}
	applyDefaults(&c)
	if err := applyEnv(&c); err != nil {
		t.Fatalf("applyEnv 失败: %v", err)
	}
	if c.Defaults.DNS.Listen != "127.0.0.1:15353" {
		t.Fatalf("HO_DNS_LISTEN 应覆盖，实际 %q", c.Defaults.DNS.Listen)
	}
	if c.Defaults.DNS.TTL != 15 {
		t.Fatalf("HO_DNS_TTL 应覆盖为 15，实际 %d", c.Defaults.DNS.TTL)
	}

	t.Setenv("HO_DNS_LISTEN", "off")
	c2 := Config{}
	applyDefaults(&c2)
	if err := applyEnv(&c2); err != nil {
		t.Fatalf("applyEnv 失败: %v", err)
	}
	if c2.Defaults.DNS.Listen != "" {
		t.Fatalf("HO_DNS_LISTEN=off 应禁用，实际 %q", c2.Defaults.DNS.Listen)
	}
}

// TestDNSValidateRejectsBadListen 验证非法监听地址在 Load/Parse 阶段被拒绝。
func TestDNSValidateRejectsBadListen(t *testing.T) {
	bad := []string{
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"1.2.3.4"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"a:b"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"1.2.3.4:0"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"example.com:18053"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":":99999"}}}`,
	}
	for _, data := range bad {
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("非法 listen 应被拒绝: %s", data)
		}
	}
	good := []string{
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"127.0.0.1:18053"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":":18053"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"0.0.0.0:5353"}}}`,
		`{"domains":[{"name":"a.com"}],"defaults":{"dns":{"listen":"off"}}}`,
	}
	for _, data := range good {
		if _, err := Parse([]byte(data)); err != nil {
			t.Fatalf("合法 listen 不应被拒绝: %s: %v", data, err)
		}
	}
}

// TestDNSValidateTTLBoundary 验证 ttl 边界：4 与 3601 报错，5 与 3600 通过。
func TestDNSValidateTTLBoundary(t *testing.T) {
	for _, ttl := range []int{4, 3601} {
		data := `{"domains":[{"name":"a.com"}],"defaults":{"dns":{"ttl":` + strconv.Itoa(ttl) + `}}}`
		if _, err := Parse([]byte(data)); err == nil {
			t.Fatalf("ttl=%d 应被拒绝", ttl)
		}
	}
	for _, ttl := range []int{5, 60, 3600} {
		data := `{"domains":[{"name":"a.com"}],"defaults":{"dns":{"ttl":` + strconv.Itoa(ttl) + `}}}`
		if _, err := Parse([]byte(data)); err != nil {
			t.Fatalf("ttl=%d 不应被拒绝: %v", ttl, err)
		}
	}
}

// TestLoadMissingFile 验证配置文件缺失时报错而非 panic。
func TestLoadMissingFile(t *testing.T) {
	t.Setenv("HO_CONFIG", os.TempDir())
	if _, err := Load(); err == nil {
		t.Fatal("配置文件缺失时应返回错误")
	}
}

// TestConfigMigrationFromLegacy 验证主路径缺失时从旧位置一次性迁移 domains.json。
func TestConfigMigrationFromLegacy(t *testing.T) {
	mainDir := t.TempDir()
	legacyDir := t.TempDir()
	content := `{"domains":[{"name":"github.com"}],"defaults":{"schedule_minutes":30}}`
	if err := os.WriteFile(filepath.Join(legacyDir, "domains.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("写旧配置失败: %v", err)
	}
	t.Setenv("HO_CONFIG", mainDir)
	t.Setenv("HO_LEGACY_CONFIG", legacyDir)

	rt, err := Load()
	if err != nil {
		t.Fatalf("应从旧位置迁移并加载: %v", err)
	}
	if len(rt.Config.Domains) != 1 || rt.Config.Domains[0].Name != "github.com" {
		t.Fatalf("迁移后域名不符: %+v", rt.Config.Domains)
	}
	if rt.Config.Defaults.ScheduleMinutes != 30 {
		t.Fatalf("迁移后调度周期不符: %d", rt.Config.Defaults.ScheduleMinutes)
	}
	// 主路径应已就位，旧文件应被移除（完成移动）。
	if _, err := os.Stat(filepath.Join(mainDir, "domains.json")); err != nil {
		t.Fatalf("迁移后主路径应存在: %v", err)
	}
	if _, err := os.Stat(filepath.Join(legacyDir, "domains.json")); !os.IsNotExist(err) {
		t.Fatal("迁移后旧文件应被移除")
	}
	// 第二次 Load 不应再触发迁移，直接读主路径。
	if _, err := Load(); err != nil {
		t.Fatalf("迁移后二次加载应成功: %v", err)
	}
}

// TestConfigMigrationNoLegacy 验证未设置 HO_LEGACY_CONFIG 时主路径缺失直接报错。
func TestConfigMigrationNoLegacy(t *testing.T) {
	mainDir := t.TempDir()
	t.Setenv("HO_CONFIG", mainDir)
	t.Setenv("HO_LEGACY_CONFIG", "")
	if _, err := Load(); err == nil {
		t.Fatal("无旧位置且主路径缺失时应报错")
	}
}

// TestConfigMigrationSameDir 验证新旧路径相同时不迁移、不误删。
func TestConfigMigrationSameDir(t *testing.T) {
	dir := t.TempDir()
	content := `{"domains":[{"name":"a.com"}]}`
	if err := os.WriteFile(filepath.Join(dir, "domains.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	t.Setenv("HO_CONFIG", dir)
	t.Setenv("HO_LEGACY_CONFIG", dir)
	if _, err := Load(); err != nil {
		t.Fatalf("新旧同路径应正常加载: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "domains.json")); err != nil {
		t.Fatalf("新旧同路径时文件不应被删除: %v", err)
	}
}

// TestExpandCacheTTL 验证子域扩展缓存 TTL 的默认值、环境变量覆盖与校验边界。
func TestExpandCacheTTL(t *testing.T) {
	c := Config{}
	applyDefaults(&c)
	if c.Defaults.ExpandCacheTTLHours != 12 {
		t.Fatalf("默认 TTL 应为 12 小时，实际 %d", c.Defaults.ExpandCacheTTLHours)
	}

	t.Setenv("HO_EXPAND_CACHE_TTL_HOURS", "48")
	c2 := Config{}
	applyDefaults(&c2)
	if err := applyEnv(&c2); err != nil {
		t.Fatalf("applyEnv 失败: %v", err)
	}
	if c2.Defaults.ExpandCacheTTLHours != 48 {
		t.Fatalf("HO_EXPAND_CACHE_TTL_HOURS 应覆盖为 48，实际 %d", c2.Defaults.ExpandCacheTTLHours)
	}

	// applyDefaults 会把 0 归一化为默认 12，故只有越界值（>240）应被拒绝。
	bad := Config{Defaults: Defaults{ExpandCacheTTLHours: 241}}
	applyDefaults(&bad)
	if err := validate(&bad); err == nil {
		t.Fatal("TTL=241 应被拒绝")
	}
	zero := Config{Defaults: Defaults{ExpandCacheTTLHours: 0}}
	applyDefaults(&zero)
	if err := validate(&zero); err != nil {
		t.Fatalf("TTL=0 应归一化为默认并合法，实际 %v", err)
	}
	ok := Config{Defaults: Defaults{ExpandCacheTTLHours: 240}}
	applyDefaults(&ok)
	if err := validate(&ok); err != nil {
		t.Fatalf("TTL=240 应合法，实际 %v", err)
	}
}

// 1.5.0 移除了 suppress_aaaa 与 outputs：旧配置里残留的这两个键
// 必须被 JSON 解析静默忽略，不导致解析失败（向后兼容）。
func TestLegacyRemovedKeysIgnored(t *testing.T) {
	raw := []byte(`{
  "domains": [{"name": "github.com", "suppress_aaaa": false}],
  "defaults": {"outputs": ["hosts.txt", "agh.txt", "status.json"]}
}`)
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("含残留键的旧配置应可解析: %v", err)
	}
	if len(c.Domains) != 1 || c.Domains[0].Name != "github.com" {
		t.Fatalf("域名解析不符: %+v", c.Domains)
	}
}
