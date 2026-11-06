// Package logbuf 在内存中保留最近的运行日志，供管理页面实时查看。
package logbuf

import (
	"strings"
	"sync"
	"time"
)

// Entry 是一条运行日志。
type Entry struct {
	Seq  uint64    `json:"seq"`
	Time time.Time `json:"time"`
	Text string    `json:"text"`
}

// Buffer 是固定容量的环形日志缓冲，可安全并发写入。
type Buffer struct {
	mu    sync.Mutex
	buf   []Entry
	start int
	count int
	seq   uint64
}

// Default 是进程级共享缓冲，main 会把 log 输出同时写入这里。
var Default = New(2000)

// New 创建指定容量的缓冲；size<=0 时使用 2000。
func New(size int) *Buffer {
	if size <= 0 {
		size = 2000
	}
	return &Buffer{buf: make([]Entry, size)}
}

func (b *Buffer) add(e Entry) {
	if b.count < len(b.buf) {
		b.buf[(b.start+b.count)%len(b.buf)] = e
		b.count++
		return
	}
	b.buf[b.start] = e
	b.start = (b.start + 1) % len(b.buf)
}

// Write 实现 io.Writer，按行拆分后写入缓冲。
func (b *Buffer) Write(p []byte) (int, error) {
	now := time.Now()
	b.mu.Lock()
	for _, raw := range strings.Split(string(p), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		b.seq++
		b.add(Entry{Seq: b.seq, Time: now, Text: line})
	}
	b.mu.Unlock()
	return len(p), nil
}

// Snapshot 返回 seq > after 的条目；after=0 时返回最近 limit 条。
func (b *Buffer) Snapshot(after uint64, limit int) []Entry {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Entry, 0, limit)
	for i := 0; i < b.count; i++ {
		e := b.buf[(b.start+i)%len(b.buf)]
		if e.Seq <= after {
			continue
		}
		out = append(out, e)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// LastSeq 返回当前最新日志序号。
func (b *Buffer) LastSeq() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seq
}
