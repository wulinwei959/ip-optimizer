// Package history 用标准库实现按轮次分片的追加式历史存储。
//
// 每轮探测的每个域名写一行 JSON，一个轮次一个 gzip JSONL 分片
// （rounds-YYYYMMDD-HHMMSS-NNNN.jsonl.gz）。追加时只写新文件，不重写旧数据，
// 因此不会像「每月一个分片」那样每轮都把整个月文件重新压缩一遍。
//
// 查询从最新分片往前读，取满 limit 条即可停止，不会把整段历史读进内存；
// 保留期外的分片自动清理。对外暴露 Store 接口，便于将来替换为 SQLite。
package history

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Record 是一条域名探测历史。
type Record struct {
	Time       time.Time `json:"time"`
	RoundID    string    `json:"round_id"`
	Domain     string    `json:"domain"`
	Group      string    `json:"group"`
	IP         string    `json:"ip,omitempty"`
	LatencyMS  float64   `json:"latency_ms"`
	Candidates int       `json:"candidates"`
	Validated  bool      `json:"validated"`
	Reason     string    `json:"reason,omitempty"`
}

// Filter 是查询条件；From/To 为零值时默认取最近 7 天。
type Filter struct {
	Domain string
	Group  string
	From   time.Time
	To     time.Time
	Limit  int
}

// Store 抽象历史存储，便于将来替换为 SQLite 实现。
type Store interface {
	Append(records []Record) error
	Query(filter Filter) ([]Record, error)
	Close() error
}

// FileStore 是基于「每轮一个 gzip JSONL 分片」的追加式实现。
type FileStore struct {
	dir       string
	retention int
	mu        sync.RWMutex
	curDay    string
	curSeq    int
}

// Open 创建历史目录并按保留期清理旧分片。
func Open(dir string, retentionMonths int) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("历史目录不能为空")
	}
	if retentionMonths <= 0 {
		retentionMonths = 12
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建历史目录失败: %w", err)
	}
	s := &FileStore{dir: dir, retention: retentionMonths}
	s.cleanupLocked(time.Now())
	return s, nil
}

func (s *FileStore) Close() error { return nil }

// Append 把一批记录写成一个分片；同一批必须属于同一个轮次（调用方按轮次写入，天然满足）。
func (s *FileStore) Append(records []Record) error {
	if len(records) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	at := records[0].Time
	if day := at.Format("20060102"); day != s.curDay {
		s.curDay = day
		s.curSeq = 0
	}
	name := fmt.Sprintf("rounds-%s-%04d.jsonl.gz", at.Format("20060102-150405"), s.curSeq)
	s.curSeq++
	path := filepath.Join(s.dir, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("打开历史分片失败: %w", err)
	}
	zw := gzip.NewWriter(f)
	enc := json.NewEncoder(zw)
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			_ = zw.Close()
			_ = f.Close()
			return fmt.Errorf("写入历史失败: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("压缩历史失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("同步历史失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭历史文件失败: %w", err)
	}
	s.cleanupLocked(time.Now())
	return nil
}

// Query 返回时间范围内的记录（按时间升序）。Limit>0 时只保留最近的 N 条。
func (s *FileStore) Query(filter Filter) ([]Record, error) {
	to := filter.To
	if to.IsZero() {
		to = time.Now()
	}
	from := filter.From
	if from.IsZero() {
		from = to.AddDate(0, 0, -7)
	}
	if from.After(to) {
		return []Record{}, nil
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	type shard struct {
		name string
		key  time.Time
	}
	shards := make([]shard, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "rounds-") || !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		key, ok := shardKey(name)
		if !ok {
			continue
		}
		shards = append(shards, shard{name: name, key: key})
	}
	// 新→旧：时间键相同的（同一天）按文件名倒序，文件名里含时分秒与序号，
	// 倒序正好是时间倒序。
	sort.Slice(shards, func(i, j int) bool {
		if !shards[i].key.Equal(shards[j].key) {
			return shards[i].key.After(shards[j].key)
		}
		return shards[i].name > shards[j].name
	})

	out := make([]Record, 0, 256)
	legacy := false
	for _, sh := range shards {
		// 旧月度分片的时间键是月初，可能明显早于它里面的记录，不能据此提前结束。
		if !isLegacyShard(sh.name) && sh.key.Before(from) {
			break
		}
		records, err := readFile(filepath.Join(s.dir, sh.name), from, to, filter)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// 损坏或截断的分片只丢弃它自己，不影响其余分片。
			if len(records) == 0 {
				continue
			}
		}
		if isLegacyShard(sh.name) {
			legacy = true
		}
		for i := len(records) - 1; i >= 0; i-- {
			out = append(out, records[i])
		}
		// 已经拿到最近 N 条，且后续分片不可能更晚，可以提前结束。
		if filter.Limit > 0 && len(out) >= filter.Limit && !legacy {
			break
		}
	}

	// 倒序收集，反转成时间升序。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[len(out)-filter.Limit:]
	}
	return out, nil
}

func monthStart(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
}

// shardKey 从分片文件名解析时间键：新格式取轮次时间（与记录时间一致），旧月度格式取月初。
func shardKey(name string) (time.Time, bool) {
	body := strings.TrimSuffix(strings.TrimPrefix(name, "rounds-"), ".jsonl.gz")
	if len(body) >= 15 {
		if t, err := time.ParseInLocation("20060102-150405", body[:15], time.Local); err == nil {
			return t, true
		}
		return time.Time{}, false
	}
	if t, err := time.ParseInLocation("200601", body, time.Local); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// isLegacyShard 判断是否为旧版「每月一个分片」的命名（rounds-YYYYMM.jsonl.gz）。
func isLegacyShard(name string) bool {
	body := strings.TrimSuffix(strings.TrimPrefix(name, "rounds-"), ".jsonl.gz")
	return !strings.Contains(body, "-")
}

func (s *FileStore) cleanupLocked(now time.Time) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	cutoff := monthStart(now).AddDate(0, -(s.retention - 1), 0)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "rounds-") || !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		key, ok := shardKey(name)
		if !ok {
			continue
		}
		if key.Before(cutoff) {
			_ = os.Remove(filepath.Join(s.dir, name))
		}
	}
}

func readFile(path string, from, to time.Time, filter Filter) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	dec := json.NewDecoder(zr)
	var out []Record
	for {
		var r Record
		if err := dec.Decode(&r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			// 崩溃可能留下截断的 gzip 成员：保留已读出部分。
			break
		}
		if r.Time.Before(from) || r.Time.After(to) {
			continue
		}
		if filter.Domain != "" && r.Domain != filter.Domain {
			continue
		}
		if filter.Group != "" && r.Group != filter.Group {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// BaseDomain 返回可注册主域名（粗略实现，覆盖常见多级后缀）。
func BaseDomain(name string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), ".")), ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) <= 2 {
		return strings.Join(out, ".")
	}
	lastTwo := out[len(out)-2] + "." + out[len(out)-1]
	if multiSuffix[lastTwo] {
		return out[len(out)-3] + "." + lastTwo
	}
	return lastTwo
}

var multiSuffix = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true,
	"com.hk": true, "com.tw": true, "com.sg": true, "com.au": true, "com.br": true,
	"co.jp": true, "co.kr": true, "co.in": true, "co.nz": true, "co.za": true,
	"com.ru": true, "com.mx": true,
}
