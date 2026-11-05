package store

import (
	"testing"
	"time"
)

func newState(ip string, latency float64) *State {
	s := &State{Domains: make(map[string]*DomainState)}
	s.Domains["example.com"] = &DomainState{IP: ip, LatencyMS: latency}
	return s
}

func TestDecideFirstAdopt(t *testing.T) {
	s := &State{Domains: make(map[string]*DomainState)}
	d := s.Decide("example.com", []Candidate{{IP: "1.2.3.4", LatencyMS: 42}}, 20, 2, time.Now())
	if d.IP != "1.2.3.4" || !d.Switched {
		t.Fatalf("首次应采用最佳 IP，得到 %+v", d)
	}
}

func TestDecideKeepsCurrentWhenBestUnchanged(t *testing.T) {
	s := newState("1.2.3.4", 42)
	d := s.Decide("example.com", []Candidate{{IP: "1.2.3.4", LatencyMS: 40}}, 20, 2, time.Now())
	if d.IP != "1.2.3.4" || d.Switched {
		t.Fatalf("最优未变时不应切换，得到 %+v", d)
	}
}

func TestDecideHysteresisNeedsConsecutiveWins(t *testing.T) {
	s := newState("1.1.1.1", 100)
	// best 改善 50%，超过 20% 阈值，但需要连续 2 轮胜出
	valid := []Candidate{{IP: "2.2.2.2", LatencyMS: 50}, {IP: "1.1.1.1", LatencyMS: 100}}
	first := s.Decide("example.com", valid, 20, 2, time.Now())
	if first.IP != "1.1.1.1" || first.Switched {
		t.Fatalf("第 1 轮胜出不应切换，得到 %+v", first)
	}
	second := s.Decide("example.com", valid, 20, 2, time.Now())
	if second.IP != "2.2.2.2" || !second.Switched {
		t.Fatalf("第 2 轮胜出应切换，得到 %+v", second)
	}
}

func TestDecideIgnoresSmallImprovement(t *testing.T) {
	s := newState("1.1.1.1", 100)
	// 改善仅 5%，低于 20% 阈值
	valid := []Candidate{{IP: "2.2.2.2", LatencyMS: 95}, {IP: "1.1.1.1", LatencyMS: 100}}
	for i := 0; i < 5; i++ {
		d := s.Decide("example.com", valid, 20, 2, time.Now())
		if d.IP != "1.1.1.1" {
			t.Fatalf("第 %d 轮小幅改善不应切换，得到 %+v", i+1, d)
		}
	}
}

func TestDecideSwitchesImmediatelyWhenCurrentInvalid(t *testing.T) {
	s := newState("1.1.1.1", 100)
	// 当前 IP 已不在通过校验的列表里，滞回不再适用
	d := s.Decide("example.com", []Candidate{{IP: "2.2.2.2", LatencyMS: 50}}, 20, 2, time.Now())
	if d.IP != "2.2.2.2" || !d.Switched {
		t.Fatalf("当前 IP 失效时应立即切换，得到 %+v", d)
	}
}

func TestDecideFailureKeepsPreviousIP(t *testing.T) {
	s := newState("1.1.1.1", 100)
	d := s.Decide("example.com", nil, 20, 2, time.Now())
	if d.IP != "1.1.1.1" || d.Switched {
		t.Fatalf("整轮全灭必须保留上一轮结果，得到 %+v", d)
	}
	if s.Domains["example.com"].ConsecutiveFailures != 1 {
		t.Fatal("应记录连续失败次数")
	}
}

func TestDecideNoHistoryNoCandidates(t *testing.T) {
	s := &State{Domains: make(map[string]*DomainState)}
	d := s.Decide("example.com", nil, 20, 2, time.Now())
	if d.IP != "" || d.Switched {
		t.Fatalf("既无历史也无候选时应返回空，得到 %+v", d)
	}
}
