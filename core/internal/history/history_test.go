package history

import (
	"os"
	"path/filepath"
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

func TestMonthlyRotation(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, 12)
	oct := testTime(2026, 10, 31, 23)
	nov := testTime(2026, 11, 1, 0)
	_ = s.Append([]Record{{Time: oct, Domain: "a.com", Group: "a.com"}})
	_ = s.Append([]Record{{Time: nov, Domain: "b.com", Group: "b.com"}})

	for _, name := range []string{"rounds-202610.jsonl.gz", "rounds-202611.jsonl.gz"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("缺少分片 %s: %v", name, err)
		}
	}
	got, _ := s.Query(Filter{From: oct.Add(-time.Hour), To: nov.Add(time.Hour)})
	if len(got) != 2 {
		t.Fatalf("跨月查询 = %d, want 2", len(got))
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
	if _, err := os.Stat(filepath.Join(dir, "rounds-202501.jsonl.gz")); !os.IsNotExist(err) {
		t.Fatalf("过期分片应被清理，err=%v", err)
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
