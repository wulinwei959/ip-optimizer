// Package output 生成 hosts.txt / agh.txt / status.json 三份产物。
package output

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// Entry 是单个域名本轮最终生效的结果。
type Entry struct {
	Name       string
	IP         string
	LatencyMS  float64
	Reason     string
	Validated  int
	Candidates int
}

// RoundInfo 是本轮探测的元信息。
type RoundInfo struct {
	StartedAt       time.Time `json:"started_at"`
	FinishedAt      time.Time `json:"finished_at"`
	OK              bool      `json:"ok"`
	Error           string    `json:"error,omitempty"`
	ScheduleMinutes int       `json:"schedule_minutes"`
	RoundID         int64     `json:"round_id,omitempty"`
}

// StatusDomain 是 status.json 中的单域名条目。
type StatusDomain struct {
	Name       string  `json:"name"`
	IP         string  `json:"ip,omitempty"`
	LatencyMS  float64 `json:"latency_ms,omitempty"`
	Candidates int     `json:"candidates"`
	Validated  int     `json:"validated"`
	Reason     string  `json:"reason"`
}

// Status 是 /status.json 的内容。
type Status struct {
	Ready           bool           `json:"ready"`
	GeneratedAt     time.Time      `json:"generated_at"`
	ScheduleMinutes int            `json:"schedule_minutes"`
	DomainCount     int            `json:"domain_count"`
	ActiveCount     int            `json:"active_count"`
	Domains         []StatusDomain `json:"domains"`
	Round           RoundInfo      `json:"round"`
}

// Snapshot 是服务在内存中持有的最新产物，HTTP 直接读它，避免每请求读磁盘。
type Snapshot struct {
	Hosts, AGH, StatusBytes        []byte
	HostsETag, AGHETag, StatusETag string
	Modified                       time.Time
	Ready                          bool
	Status                         Status
}

// ETag 由内容生成弱无关的强校验值，供 AdGuard Home 条件请求使用。
func ETag(data []byte) string {
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

// Build 生成三份产物字节。Ready=false 表示没有任何生效 IP。
func Build(entries []Entry, now time.Time, round RoundInfo) (*Snapshot, error) {
	st := Status{
		GeneratedAt:     now,
		ScheduleMinutes: round.ScheduleMinutes,
		DomainCount:     len(entries),
		Domains:         make([]StatusDomain, 0, len(entries)),
		Round:           round,
	}

	var hosts, agh bytes.Buffer
	fmt.Fprintf(&hosts, "# hosts-optimizer | %s | 每 %d 分钟更新\n", now.Format(time.RFC3339), round.ScheduleMinutes)
	fmt.Fprintf(&hosts, "# /etc/hosts 语法为精确匹配，不覆盖子域；需要子域请用 agh.txt\n")
	fmt.Fprintf(&agh, "! hosts-optimizer | %s | 每 %d 分钟更新\n", now.Format(time.RFC3339), round.ScheduleMinutes)
	fmt.Fprintf(&agh, "! ||domain^ 同时匹配子域；dnsrewrite 规则会替换该域名整个 DNS 应答，\n")
	fmt.Fprintf(&agh, "! AAAA 查询因应答中无 AAAA 记录而返回 NODATA，天然避免 IPv6 绕过。\n")
	fmt.Fprintf(&agh, "! 因此不输出「空 AAAA 值」的 dnsrewrite 规则：urlfilter 要求该 VALUE 必须是合法 IPv6，空值会被判为非法。\n")

	active := 0
	for _, e := range entries {
		sd := StatusDomain{
			Name: e.Name, IP: e.IP, LatencyMS: round1(e.LatencyMS),
			Candidates: e.Candidates, Validated: e.Validated,
			Reason: e.Reason,
		}
		st.Domains = append(st.Domains, sd)
		if e.IP == "" {
			continue
		}
		active++
		fmt.Fprintf(&hosts, "%s %s\n", e.IP, e.Name)
		// 官方语法：RCODE;RRTYPE;VALUE。NOERROR;A;IP 返回指定 A 记录。
		fmt.Fprintf(&agh, "||%s^$dnsrewrite=NOERROR;A;%s\n", e.Name, e.IP)
	}
	fmt.Fprintf(&hosts, "# 规则数: %d\n", active)
	fmt.Fprintf(&agh, "! 规则数: %d\n", active)

	st.ActiveCount = active
	st.Ready = active > 0
	statusBytes, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化 status.json 失败: %w", err)
	}
	statusBytes = append(statusBytes, '\n')

	return &Snapshot{
		Hosts: hosts.Bytes(), AGH: agh.Bytes(), StatusBytes: statusBytes,
		HostsETag: ETag(hosts.Bytes()), AGHETag: ETag(agh.Bytes()), StatusETag: ETag(statusBytes),
		Modified: now, Ready: st.Ready, Status: st,
	}, nil
}
