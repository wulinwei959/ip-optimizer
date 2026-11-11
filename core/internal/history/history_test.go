package history

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTime(year int, month time.Month, day, hour int) time.Time {
	return time.Date(year, month, day, hour, 0, 0, 0, time.Local)
}

func TestAppendAndQuery(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 12)
	if err != nil {
		t.Fatal(err)
	}
	now := testTime(2026, 11, 7, 10)
	records := []Record{
		{Time: now, RoundID: "r1", Domain: "www.github.com", Group: "github.com", IP: "1.1.1.1", LatencyMS: 12.5, Candidates: 2, Validated: true},
		{Time: now, RoundID: "r1", Domain: "api.gitlab.com", Group: "gitlab.com", IP: "2.2.2.2", LatencyMS: 30, Candidates: 1, Validated: true},
	}
	if err := s.Append(records); err != nil {
		t.Fatal(err)
	}
	got, err := s.Query(Filter{From: now.Add(-time.Hour), To: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("记录数 = %d, want 2", len(got))
	}
	if got[0].Domain != "www.github.com" || got[1].Domain != "api.gitlab.com" {
		t.Fatalf("顺序或内容不符: %+v", got)
	}
}

func TestQueryFiltersAndLimit(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 12)
	base := testTime(2026, 11, 7, 10)
	var records []Record
	for i := 0; i < 5; i++ {
		records = append(records, Record{
			Time: base.Add(time.Duration(i) * time.Minute), RoundID: "r1",
			Domain: "github.com", Group: "github.com", Validated: true,
		})
	}
	records = append(records, Record{
		Time: base, RoundID: "r1", Domain: "gitlab.com", Group: "gitlab.com", Validated: true,
	})
	if err := s.Append(records); err != nil {
		t.Fatal(err)
	}
	got, err := s.Query(Filter{Domain: "github.com", From: base.Add(-time.Hour), To: base.Add(time.Hour), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("limit 结果 = %d, want 2", len(got))
	}
	if !got[0].Time.Equal(base.Add(3*time.Minute)) || !got[1].Time.Equal(base.Add(4*time.Minute)) {
		t.Fatalf("limit 应保留最近两条: %+v", got)
	}
	group, _ := s.Query(Filter{Group: "gitlab.com", From: base.Add(-time.Hour), To: base.Add(time.Hour)})
	if len(group) != 1 {
		t.Fatalf("按分组查询 = %d, want 1", len(group))
	}
}

// 一个轮次一个分片：跨月写入后应得到两个分片，且跨月查询都能读到。
func TestShardPerRoundCrossMonth(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 12)
	oct := testTime(2026, 10, 31, 23)
	nov := testTime(2026, 11, 1, 0)
	if err := s.Append([]Record{{Time: oct, Domain: "a.com", Group: "a.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]Record{{Time: nov, Domain: "b.com", Group: "b.com"}}); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	shards := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "rounds-") && strings.HasSuffix(e.Name(), ".jsonl.gz") {
			shards++
		}
	}
	if shards != 2 {
		t.Fatalf("每个轮次一个分片，实际 %d 个", shards)
	}

	got, _ := s.Query(Filter{From: oct.Add(-time.Hour), To: nov.Add(time.Hour)})
	if len(got) != 2 {
		t.Fatalf("跨月查询 = %d, want 2", len(got))
	}
	if !got[0].Time.Equal(oct) || !got[1].Time.Equal(nov) {
		t.Fatalf("跨月查询顺序不符: %+v", got)
	}
}

// 多轮次写入后，limit 只保留最近 N 条，且整体按时间升序。
func TestMultipleRoundsKeepsRecentAndOrders(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 12)
	base := testTime(2026, 11, 7, 10)
	for i := 0; i < 5; i++ {
		rec := []Record{{
			Time: base.Add(time.Duration(i) * time.Hour), RoundID: "r",
			Domain: "github.com", Group: "github.com", Validated: true,
		}}
		if err := s.Append(rec); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.Query(Filter{Domain: "github.com", From: base.Add(-time.Hour), To: base.Add(6 * time.Hour), Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("limit 结果 = %d, want 2", len(got))
	}
	if !got[0].Time.Equal(base.Add(3*time.Hour)) || !got[1].Time.Equal(base.Add(4*time.Hour)) {
		t.Fatalf("应保留最近两条且升序: %+v", got)
	}
}

func TestRetentionCleanup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	old := testTime(2025, 1, 15, 10)
	recent := time.Now()
	if err := s.Append([]Record{{Time: old, Domain: "old.com", Group: "old.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]Record{{Time: recent, Domain: "new.com", Group: "new.com"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "rounds-202501") {
			t.Fatalf("过期分片应被清理: %s", e.Name())
		}
	}
}

// 旧版「每月一个分片」的历史仍应可读：升级后趋势图不会突然全空。
func TestLegacyMonthlyShardStillReadable(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 12)
	legacy := testTime(2026, 11, 7, 10)

	f, err := os.Create(filepath.Join(dir, "rounds-202611.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(Record{
		Time: legacy, RoundID: "old", Domain: "old.com", Group: "old.com",
		IP: "1.1.1.1", Validated: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := s.Query(Filter{Domain: "old.com", From: legacy.Add(-time.Hour), To: legacy.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Domain != "old.com" {
		t.Fatalf("旧月度分片应可读，得到 %+v", got)
	}
}

func TestBaseDomain(t *testing.T) {
	cases := map[string]string{
		"github.com":                "github.com",
		"api.gitlab.com":            "gitlab.com",
		"raw.githubusercontent.com": "githubusercontent.com",
		"a.b.example.com.cn":        "example.com.cn",
		"example.co.uk":             "example.co.uk",
		"localhost":                 "localhost",
	}
	for in, want := range cases {
		if got := BaseDomain(in); got != want {
			t.Errorf("BaseDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
