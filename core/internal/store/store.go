// Package store 持久化每个域名的当前生效 IP，并实现滞回防抖与「失败不覆盖」。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"hosts-optimizer/internal/util"
)

// Candidate 是一个本轮通过校验的 IP 及其延迟。
type Candidate struct {
	IP        string  `json:"ip"`
	LatencyMS float64 `json:"latency_ms"`
}

// DomainState 是单个域名的切换状态。
type DomainState struct {
	IP                  string      `json:"ip"`
	LatencyMS           float64     `json:"latency_ms"`
	ChallengerIP        string      `json:"challenger_ip,omitempty"`
	ChallengerWins      int         `json:"challenger_wins,omitempty"`
	LastCheck           time.Time   `json:"last_check"`
	LastSwitch          time.Time   `json:"last_switch,omitempty"`
	ConsecutiveFailures int         `json:"consecutive_failures,omitempty"`
	ValidatedLastRound  int         `json:"validated_last_round,omitempty"`
	Candidates          []Candidate `json:"candidates,omitempty"`
}

// State 是写进 $HO_STATE/state.json 的整体状态。
type State struct {
	UpdatedAt time.Time               `json:"updated_at"`
	Domains   map[string]*DomainState `json:"domains"`

	// 异步落盘用
	mu   sync.Mutex
	path string
	wg   sync.WaitGroup
}

// Storer 定义状态存储接口，便于未来替换为 SQLite 等实现。
type Storer interface {
	Save(path string, now time.Time) error
	// Snapshot 在调用方持有的写锁内序列化整个状态，返回可直接落盘的字节。
	Snapshot(now time.Time) []byte
	// SaveAsync 异步落盘；data 必须来自 Snapshot，本方法不再触碰 State 内部数据。
	SaveAsync(path string, data []byte)
	Decide(name string, valid []Candidate, percent, rounds int, now time.Time) Decision
	// AllDomains 返回底层域名状态映射，供直接读写（如手动切换 IP、查询候选）。
	AllDomains() map[string]*DomainState
	// SetUpdatedAt 更新时间戳（Snapshot 内部会调用，外部一般无需调用）。
	SetUpdatedAt(time.Time)
}

// 确保 *State 实现 Storer
var _ Storer = (*State)(nil)

// Load 读取状态；文件不存在或损坏时返回空状态，不让服务起不来。
func Load(path string) (*State, bool, error) {
	s := &State{Domains: make(map[string]*DomainState), path: path}
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

// Snapshot 序列化整个状态，返回可直接落盘的字节（末尾带换行）。
//
// 必须在调用方持有的写锁内调用（App 里是 stateMu）：Domains map 的并发读写由调用方
// 串行化，State 自身的 s.mu 只保护 UpdatedAt。若把序列化挪到写盘的 goroutine 里，
// 就会与并发执行的 Decide 撞上「并发 map 读写」，Go 会直接 fatal 终止进程。
func (s *State) Snapshot(now time.Time) []byte {
	s.mu.Lock()
	s.UpdatedAt = now
	b, err := json.MarshalIndent(s, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return nil
	}
	return append(b, '\n')
}

// Save 同步原子写状态文件（兼容旧调用）。
func (s *State) Save(path string, now time.Time) error {
	b := s.Snapshot(now)
	if b == nil {
		return errors.New("序列化状态失败")
	}
	return util.AtomicWrite(path, b)
}

// SaveAsync 异步落盘：字节快照由调用方在锁内生成，本方法只负责写盘，不阻塞调用方。
func (s *State) SaveAsync(path string, data []byte) {
	if len(data) == 0 {
		return
	}
	s.wg.Add(1)
	go func(p string, b []byte) {
		defer s.wg.Done()
		_ = util.AtomicWrite(p, b)
	}(path, data)
}

// WaitSave 等待所有异步落盘完成（测试/关闭时用）。
func (s *State) WaitSave() {
	s.wg.Wait()
}

// AllDomains 实现 Storer 接口。
func (s *State) AllDomains() map[string]*DomainState {
	return s.Domains
}

// SetUpdatedAt 实现 Storer 接口。
func (s *State) SetUpdatedAt(t time.Time) {
	s.mu.Lock()
	s.UpdatedAt = t
	s.mu.Unlock()
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
	st.Candidates = append([]Candidate(nil), valid...)

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
