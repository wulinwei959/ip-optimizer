// Package store 持久化每个域名的当前生效 IP，并实现滞回防抖与「失败不覆盖」。
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"hosts-optimizer/internal/util"
)

// Candidate 是一个本轮通过校验的 IP 及其延迟。
type Candidate struct {
	IP        string
	LatencyMS float64
}

// DomainState 是单个域名的切换状态。
type DomainState struct {
	IP                  string    `json:"ip"`
	LatencyMS           float64   `json:"latency_ms"`
	ChallengerIP        string    `json:"challenger_ip,omitempty"`
	ChallengerWins      int       `json:"challenger_wins,omitempty"`
	LastCheck           time.Time `json:"last_check"`
	LastSwitch          time.Time `json:"last_switch,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures,omitempty"`
	ValidatedLastRound  int       `json:"validated_last_round,omitempty"`
}

// State 是写进 $HO_STATE/state.json 的整体状态。
type State struct {
	UpdatedAt time.Time               `json:"updated_at"`
	Domains   map[string]*DomainState `json:"domains"`
}

// Load 读取状态；文件不存在或损坏时返回空状态，不让服务起不来。
func Load(path string) (*State, bool, error) {
	s := &State{Domains: make(map[string]*DomainState)}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, false, nil
		}
		return s, false, fmt.Errorf("读取状态文件失败: %w", err)
	}
	if err := json.Unmarshal(b, s); err != nil {
		return s, true, fmt.Errorf("状态文件损坏，已忽略: %w", err)
	}
	if s.Domains == nil {
		s.Domains = make(map[string]*DomainState)
	}
	return s, false, nil
}

// Save 原子写状态文件。
func (s *State) Save(path string, now time.Time) error {
	s.UpdatedAt = now
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return util.AtomicWrite(path, append(b, '\n'))
}

// Decision 是本轮最终生效的结果。
type Decision struct {
	IP        string
	LatencyMS float64
	Switched  bool
	Reason    string
	Validated int
}

// Decide 应用滞回策略，返回本轮应写入产物的 IP。
// valid 必须已按延迟升序排列；percent 是「需快至少百分之多少」，rounds 是「连续胜出多少轮」。
func (s *State) Decide(name string, valid []Candidate, percent, rounds int, now time.Time) Decision {
	st := s.Domains[name]
	if st == nil {
		st = &DomainState{}
		s.Domains[name] = st
	}
	st.LastCheck = now
	st.ValidatedLastRound = len(valid)

	if len(valid) == 0 {
		st.ConsecutiveFailures++
		if st.IP != "" {
			// 整轮全灭：保留上一轮结果，绝不写空文件。
			return Decision{IP: st.IP, LatencyMS: st.LatencyMS, Reason: "本轮无可用 IP，保留上一轮结果"}
		}
		return Decision{Reason: "本轮无可用 IP，且无历史结果"}
	}
	st.ConsecutiveFailures = 0
	best := valid[0]

	if st.IP == "" {
		st.IP, st.LatencyMS, st.LastSwitch = best.IP, best.LatencyMS, now
		st.ChallengerIP, st.ChallengerWins = "", 0
		return Decision{IP: best.IP, LatencyMS: best.LatencyMS, Switched: true, Reason: "首次采用", Validated: len(valid)}
	}

	// 当前 IP 本轮的实测延迟；若它已不在通过校验的列表里，说明它失效了。
	curLat := st.LatencyMS
	curStillValid := false
	for _, v := range valid {
		if v.IP == st.IP {
			curLat, curStillValid = v.LatencyMS, true
			break
		}
	}

	if best.IP == st.IP {
		st.LatencyMS = best.LatencyMS
		st.ChallengerIP, st.ChallengerWins = "", 0
		return Decision{IP: st.IP, LatencyMS: st.LatencyMS, Reason: "保持当前最优", Validated: len(valid)}
	}

	if !curStillValid {
		// 当前生效 IP 连 TLS 校验都过不了，滞回没有意义，立即切换。
		old := st.IP
		st.IP, st.LatencyMS, st.LastSwitch = best.IP, best.LatencyMS, now
		st.ChallengerIP, st.ChallengerWins = "", 0
		return Decision{
			IP: best.IP, LatencyMS: best.LatencyMS, Switched: true,
			Reason: fmt.Sprintf("当前 IP %s 未通过校验，立即切换", old), Validated: len(valid),
		}
	}

	improve := 0.0
	if curLat > 0 {
		improve = (curLat - best.LatencyMS) / curLat * 100
	}
	if improve < float64(percent) {
		st.ChallengerIP, st.ChallengerWins = "", 0
		return Decision{
			IP: st.IP, LatencyMS: curLat,
			Reason: fmt.Sprintf("改善 %.1f%% 未达阈值 %d%%，不切换", improve, percent), Validated: len(valid),
		}
	}

	if st.ChallengerIP != best.IP {
		st.ChallengerIP, st.ChallengerWins = best.IP, 1
	} else {
		st.ChallengerWins++
	}
	if st.ChallengerWins >= rounds {
		old := st.IP
		st.IP, st.LatencyMS, st.LastSwitch = best.IP, best.LatencyMS, now
		st.ChallengerIP, st.ChallengerWins = "", 0
		return Decision{
			IP: best.IP, LatencyMS: best.LatencyMS, Switched: true,
			Reason: fmt.Sprintf("连续 %d 轮胜出，%s → %s", rounds, old, best.IP), Validated: len(valid),
		}
	}
	return Decision{
		IP: st.IP, LatencyMS: curLat,
		Reason: fmt.Sprintf("候选 %s 胜出 %d/%d 轮，暂不切换", best.IP, st.ChallengerWins, rounds), Validated: len(valid),
	}
}
