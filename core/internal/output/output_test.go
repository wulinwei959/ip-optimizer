package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func testEntries() []Entry {
	return []Entry{
		{Name: "github.com", IP: "140.82.114.4", LatencyMS: 42.36, Reason: "首次采用", Candidates: 12, Validated: 5},
		{Name: "raw.githubusercontent.com", IP: "185.199.108.133", LatencyMS: 55.1, Reason: "保持当前最优", Candidates: 8, Validated: 4},
	}
}

func TestBuildProducesHostsAndDNSRewriteRules(t *testing.T) {
	now := time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC)
	snap, err := Build(testEntries(), now, RoundInfo{StartedAt: now, FinishedAt: now, OK: true, ScheduleMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	hosts := string(snap.Hosts)
	agh := string(snap.AGH)

	if !strings.Contains(hosts, "140.82.114.4 github.com\n") {
		t.Fatalf("hosts.txt 缺少规则:\n%s", hosts)
	}
	if !strings.Contains(agh, "||github.com^$dnsrewrite=NOERROR;A;140.82.114.4\n") {
		t.Fatalf("agh.txt 缺少 dnsrewrite 规则:\n%s", agh)
	}
	// 空 AAAA 值不是合法规则，任何非注释行都不得出现
	for _, line := range strings.Split(agh, "\n") {
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		if strings.Contains(line, "AAAA;") {
			t.Fatalf("agh.txt 输出了非法 AAAA 规则 %q:\n%s", line, agh)
		}
	}
	if !snap.Ready || snap.Status.ActiveCount != 2 || snap.Status.DomainCount != 2 {
		t.Fatalf("统计异常: %+v", snap.Status)
	}
	if snap.HostsETag == "" || snap.HostsETag == snap.AGHETag {
		t.Fatal("ETag 应存在且随内容不同")
	}
	var parsed Status
	if err := json.Unmarshal(snap.StatusBytes, &parsed); err != nil {
		t.Fatalf("status.json 非法: %v", err)
	}
	if parsed.Domains[0].LatencyMS != 42.4 {
		t.Fatalf("延迟应保留 1 位小数，得到 %v", parsed.Domains[0].LatencyMS)
	}
}

func TestBuildMarksNotReadyWhenNoActiveIP(t *testing.T) {
	now := time.Now()
	snap, err := Build([]Entry{{Name: "example.com", Reason: "本轮无可用 IP，且无历史结果"}}, now,
		RoundInfo{StartedAt: now, FinishedAt: now, OK: true, ScheduleMinutes: 60})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Ready || snap.Status.ActiveCount != 0 {
		t.Fatal("无生效 IP 时 Ready 必须为 false")
	}
	if strings.Contains(string(snap.Hosts), "example.com\n") {
		t.Fatal("不应凭空生成一条规则")
	}
}

func TestETagChangesWithContent(t *testing.T) {
	a := ETag([]byte("1.2.3.4 example.com"))
	b := ETag([]byte("5.6.7.8 example.com"))
	if a == b || !strings.HasPrefix(a, `"`) {
		t.Fatalf("ETag 生成异常: %q %q", a, b)
	}
}
