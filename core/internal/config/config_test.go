package config

import (
	"os"
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
