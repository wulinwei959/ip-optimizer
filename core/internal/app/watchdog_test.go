package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/probe"
	"hosts-optimizer/internal/store"
)

// startWatchTLS 起一个自签 TLS 服务，返回端口与信任它的根证书池。
func startWatchTLS(t *testing.T, sni string) (int, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: sni},
		DNSNames:              []string{sni},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pool
}

// 当前 IP 失效时应被标记，触发即时轮次。
func TestCheckCurrentIPsFlagsDeadIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	targets := []watchTarget{{Name: "dead.test", IP: "127.0.0.1", SNI: "dead.test", Port: port}}
	got := checkCurrentIPs(context.Background(), targets, config.Defaults{TimeoutSeconds: 2}, nil)
	if len(got) != 1 || got[0].Name != "dead.test" {
		t.Fatalf("失效的当前 IP 应被标记，得到 %+v", got)
	}
}

// 健康的当前 IP 不应被标记：否则每个探测周期都会触发一次即时轮次。
func TestCheckCurrentIPsKeepsHealthy(t *testing.T) {
	port, pool := startWatchTLS(t, "ok.test")
	targets := []watchTarget{{
		Name: "ok.test", IP: "127.0.0.1", SNI: "ok.test", Port: port, BaselineLatencyMS: 500,
	}}
	got := checkCurrentIPs(context.Background(), targets, config.Defaults{
		TimeoutSeconds: 2, WatchSwitchPercent: 20,
	}, pool)
	if len(got) != 0 {
		t.Fatalf("健康的当前 IP 不应被标记，得到 %+v", got)
	}
}

func TestIsDegradedThreshold(t *testing.T) {
	tgt := watchTarget{Name: "a.test", BaselineLatencyMS: 100}
	if isDegraded(probe.Result{LatencyMS: 120}, tgt, 20) {
		t.Fatal("慢 20% 未超过阈值，不应触发")
	}
	if !isDegraded(probe.Result{LatencyMS: 121}, tgt, 20) {
		t.Fatal("超过 20% 阈值应触发")
	}
	if isDegraded(probe.Result{LatencyMS: 100000}, watchTarget{Name: "b.test"}, 20) {
		t.Fatal("没有历史延迟时不应做「变慢」判断")
	}
}

// baselineLatency 只认「当前 IP 自己」的上一轮延迟，认不出来就返回 0。
func TestBaselineLatencyUsesCurrentIP(t *testing.T) {
	st := &store.DomainState{
		IP: "9.9.9.9",
		Candidates: []store.Candidate{
			{IP: "1.1.1.1", LatencyMS: 10}, // 最快但不是当前 IP
			{IP: "9.9.9.9", LatencyMS: 40}, // 当前 IP
		},
	}
	if got := baselineLatency(st); got != 40 {
		t.Fatalf("基准应取当前 IP 自己的延迟，得到 %v", got)
	}
	// 当前 IP 不在候选里：没有可比基准，只按存活判断。
	st2 := &store.DomainState{IP: "2.2.2.2", Candidates: []store.Candidate{{IP: "3.3.3.3", LatencyMS: 7}}}
	if got := baselineLatency(st2); got != 0 {
		t.Fatalf("当前 IP 不在候选里时应返回 0，得到 %v", got)
	}
}

// 退避：同一域名在退避窗口内不应重复触发；没换掉 IP 时退避翻倍，换掉了则恢复。
func TestWatchBackoff(t *testing.T) {
	a := &App{}
	now := time.Now()
	base := time.Minute

	if !a.shouldTriggerWatch("a.com", now, base) {
		t.Fatal("首次触发不应被退避挡住")
	}

	// 没换掉 IP（只是抖动）：退避翻倍到 2 分钟
	a.markTriggered([]string{"a.com"}, now, base, map[string]bool{"a.com": false})
	if a.shouldTriggerWatch("a.com", now.Add(30*time.Second), base) {
		t.Fatal("退避窗口内不应重复触发")
	}
	if !a.shouldTriggerWatch("a.com", now.Add(2*time.Minute), base) {
		t.Fatal("超过退避窗口后应允许再次触发")
	}

	a.markTriggered([]string{"a.com"}, now.Add(2*time.Minute), base, map[string]bool{"a.com": false})
	if a.shouldTriggerWatch("a.com", now.Add(3*time.Minute), base) {
		t.Fatal("第二次仍未换掉 IP，退避应翻倍到 4 分钟")
	}
	if !a.shouldTriggerWatch("a.com", now.Add(6*time.Minute+time.Second), base) {
		t.Fatal("超过翻倍后的退避窗口应允许触发")
	}

	// 这次真的换掉了 IP：恢复正常节奏
	a.markTriggered([]string{"a.com"}, now.Add(6*time.Minute), base, map[string]bool{"a.com": true})
	if !a.shouldTriggerWatch("a.com", now.Add(7*time.Minute), base) {
		t.Fatal("换掉 IP 后应恢复基础退避")
	}
}

// 只有上一轮通过校验的域名才进入健康探针：已经确认无可用候选的域名再探也是空转。
func TestWatchTargetsSkipsUnvalidatedDomains(t *testing.T) {
	a := &App{state: &store.State{Domains: map[string]*store.DomainState{
		"ok.com":    {IP: "1.1.1.1", ValidatedLastRound: 3, Candidates: []store.Candidate{{IP: "1.1.1.1", LatencyMS: 10}}},
		"dead.com":  {IP: "2.2.2.2", ValidatedLastRound: 0, Candidates: []store.Candidate{{IP: "2.2.2.2", LatencyMS: 5}}},
		"empty.com": {IP: ""},
	}}}
	cfg := config.Config{Domains: []config.Domain{
		{Name: "ok.com"}, {Name: "dead.com"}, {Name: "empty.com"}, {Name: "missing.com"},
	}}
	got := a.watchTargets(cfg)
	names := make([]string, 0, len(got))
	for _, t := range got {
		names = append(names, t.Name)
	}
	if len(names) != 1 || names[0] != "ok.com" {
		t.Fatalf("只应检查上一轮通过校验的域名，得到 %v", names)
	}
}

// 配置中已删除的域名，其退避状态应在 watchTargets 构建时被清理。
func TestWatchTargetsPrunesRemovedStates(t *testing.T) {
	a := &App{
		state:       &store.State{Domains: map[string]*store.DomainState{}},
		watchStates: map[string]watchState{"gone.com": {last: time.Now(), backoff: time.Minute}},
	}
	cfg := config.Config{Domains: []config.Domain{{Name: "ok.com"}}}
	a.watchTargets(cfg)
	if _, ok := a.watchStates["gone.com"]; ok {
		t.Fatal("配置中已删除域名的退避状态应被修剪")
	}
	if a.watchStatesSize.Load() != 0 {
		t.Fatalf("修剪后规模应为 0，实际 %d", a.watchStatesSize.Load())
	}
}

// 本轮全部健康时，退避状态被重置（下次触发回落基础退避）。
func TestResetWatchBackoffOnHealthy(t *testing.T) {
	a := &App{watchStates: map[string]watchState{"a.com": {last: time.Now(), backoff: 4 * time.Minute}}}
	a.resetWatchBackoff([]watchTarget{{Name: "a.com"}})
	if _, ok := a.watchStates["a.com"]; ok {
		t.Fatal("健康后应删除退避状态")
	}
}
