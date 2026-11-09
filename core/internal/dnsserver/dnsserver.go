// Package dnsserver 实现一个极简 UDP DNS 应答器：授权式应答，不做递归。
// 存在的唯一目的是让 AdGuard Home 能按域名分流直连本服务，
// 从而把「IP 切换生效时间」从 AGH 过滤器订阅刷新间隔（最低 1 小时）
// 降低到本服务设置的 TTL（默认 60 秒）。
//
// 只承诺 A / AAAA 两类查询，语义与 agh.txt 的 dnsrewrite 规则对齐：
//   - 命中且有生效 IP  → NOERROR + 1 条 A 记录
//   - 命中但无 IP      → REFUSED（宁可解析失败，不返回旧 IP 或假 IP）
//   - 清单外域名       → REFUSED + 限频日志
//   - 畸形报文         → FORMERR（QDCOUNT 置 0）或静默丢弃
package dnsserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// DNS 常量：只实现最小必需子集。
const (
	flagQR         = 1 << 15 // 查询/应答标志位
	flagRD         = 1 << 8  // 期望递归
	flagRA         = 1 << 7  // 递归可用
	opcodeMask     = 0x7800  // opcode 掩码
	opcodeQuery    = 0       // 标准查询
	rcodeMask      = 0x000F  // RCODE 掩码
	rcodeNoError   = 0
	rcodeFormErr   = 1
	rcodeRefused   = 5
	typeA          = 1
	typeAAAA       = 28
	classIN        = 1
	maxUDPSize     = 4096 // 读缓冲；应答远小于 512
	maxDomainBytes = 255  // 域名总长上限（RFC 1035）
	maxLabelBytes  = 63   // 单个 label 上限
	maxNameLabels  = 127  // label 数量上限，配合总长防环形压缩
	headerSize     = 12   // DNS 报文头长度
)

// Record 是一条应答记录。Name 必须为规范化小写且无尾点；
// IP 为空字符串表示「命中但本轮无可用 IP」。
type Record struct {
	Name string
	IP   string
}

// View 是构建后只读的应答视图，可被多个 goroutine 并发查询。
// 查询名向父域逐级回退：a.b.c → b.c → c，命中即返回。
// 语义与 AGH 的 ||domain^ 一致：Q == D 或 Q 以 .D 结尾。
type View struct {
	records map[string]Record
	ttl     uint32
}

// NewView 构建视图。空 records 等价于「全 REFUSED」空视图。
func NewView(records []Record, ttl int) *View {
	v := &View{
		records: make(map[string]Record, len(records)),
		ttl:     uint32(ttl),
	}
	for _, r := range records {
		name := normalizeName(r.Name)
		if name == "" {
			continue
		}
		if prev, dup := v.records[name]; dup {
			// 规范化后同名只保留一条，明确记下覆盖关系，避免静默丢失更高优先级记录。
			log.Printf("[dnsserver] 规范化后同名记录 %q：%s 覆盖 %s", name, r.IP, prev.IP)
		}
		v.records[name] = Record{Name: name, IP: r.IP}
	}
	return v
}

// normalizeName 规范化域名：去空白、转小写、去尾点。
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Lookup 按「精确匹配 + 父域回退」查找。
// 第二个返回值表示该查询名是否被本视图管辖（命中配置域名）。
func (v *View) Lookup(name string) (Record, bool) {
	if v == nil || len(v.records) == 0 {
		return Record{}, false
	}
	q := normalizeName(name)
	if q == "" {
		return Record{}, false
	}
	if r, ok := v.records[q]; ok {
		return r, true
	}
	// 逐级去掉最左侧标签向上找父域：a.b.c → b.c → c
	// 迭代上限为标签数：正常域名剥到根即结束，畸形输入也不会无限空转。
	for hops := 0; hops < maxNameLabels; hops++ {
		dot := strings.IndexByte(q, '.')
		if dot < 0 || dot == len(q)-1 {
			break
		}
		q = q[dot+1:]
		if r, ok := v.records[q]; ok {
			return r, true
		}
	}
	return Record{}, false
}

// Stats 是应答器的运行计数，供 /api/dns 展示。
type Stats struct {
	Queries     uint64    `json:"queries"`
	Answered    uint64    `json:"answered"`
	Nodata      uint64    `json:"nodata"`
	Refused     uint64    `json:"refused"`
	Malformed   uint64    `json:"malformed"`
	LastQueryAt time.Time `json:"last_query_at"`
	Started     bool      `json:"started"`
}

// Server 是 UDP DNS 应答器。listen 为空字符串时 New 返回 nil（禁用），
// 所有公开方法均对 nil 接收者安全，便于调用方无条件调用。
type Server struct {
	listen string
	view   atomic.Pointer[View]

	// conn 必须用 atomic：Addr() 需要在 Serve 之前（端口 0 场景）和之后都能安全读。
	conn atomic.Pointer[net.UDPConn]

	started atomic.Bool

	queries     atomic.Uint64
	answered    atomic.Uint64
	nodata      atomic.Uint64
	refused     atomic.Uint64
	malformed   atomic.Uint64
	lastQueryAt atomic.Int64 // UnixNano，0 表示从未收到查询

	missCount  atomic.Uint64 // 清单外 miss 计数，用于限频日志
	missLastLog atomic.Int64 // 最近一次打印 miss 日志的 UnixNano（时间窗限频）
}

// New 创建应答器；listen 为空字符串表示禁用，返回 nil。
func New(listen string) *Server {
	if strings.TrimSpace(listen) == "" {
		return nil
	}
	return &Server{listen: listen}
}

// SetView 原子替换应答视图。nil 接收者安全。
func (s *Server) SetView(v *View) {
	if s == nil {
		return
	}
	s.view.Store(v)
}

// Listen 返回配置的监听地址。nil 接收者返回空串。
func (s *Server) Listen() string {
	if s == nil {
		return ""
	}
	return s.listen
}

// Addr 返回实际监听地址（Serve 之后才有意义，支持端口 0 场景）。
// Serve 之前返回配置的 listen。nil 接收者返回空串。
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	if c := s.conn.Load(); c != nil {
		return c.LocalAddr().String()
	}
	return s.listen
}

// Started 表示是否已完成监听。
func (s *Server) Started() bool {
	if s == nil {
		return false
	}
	return s.started.Load()
}

// Stats 读取运行计数。nil 接收者返回零值。
func (s *Server) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	last := time.Time{}
	if ns := s.lastQueryAt.Load(); ns > 0 {
		last = time.Unix(0, ns)
	}
	return Stats{
		Queries:     s.queries.Load(),
		Answered:    s.answered.Load(),
		Nodata:      s.nodata.Load(),
		Refused:     s.refused.Load(),
		Malformed:   s.malformed.Load(),
		LastQueryAt: last,
		Started:     s.started.Load(),
	}
}

// Serve 监听并应答，直到 ctx 取消。监听失败属致命错误，直接返回。
// nil 接收者为 no-op。
func (s *Server) Serve(ctx context.Context) error {
	if s == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", s.listen)
	if err != nil {
		return fmt.Errorf("解析 DNS 监听地址 %q 失败: %w", s.listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("监听 DNS %s 失败: %w", s.listen, err)
	}
	s.conn.Store(conn)
	s.started.Store(true)
	defer func() {
		s.started.Store(false)
		_ = conn.Close()
	}()

	buf := make([]byte, maxUDPSize)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// 读错误不应拖死进程：记录一次然后继续。
			continue
		}
		if n < headerSize {
			// 短于头部的报文无从判断类型：计数后静默丢弃，不制造应答。
			s.queries.Add(1)
			s.malformed.Add(1)
			continue
		}
		// 每包一个 goroutine：家宽量级绰绰有余。
		// recover 兜底：应答器 panic 绝不能拖死整个服务。
		packet := make([]byte, n)
		copy(packet, buf[:n])
		go func(remote *net.UDPAddr, packet []byte) {
			defer func() { _ = recover() }()
			s.handlePacket(conn, remote, packet)
		}(remote, packet)
	}
}

// query 是解析后的最小查询信息。
type query struct {
	id       uint16
	flags    uint16
	qtype    uint16
	qclass   uint16
	name     string // 规范化的查询名
	question []byte // 原始 question 段（name + qtype + qclass），应答原样回显
}

// handlePacket 解析并应答单个 UDP 包。
func (s *Server) handlePacket(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) {
	s.queries.Add(1)
	s.lastQueryAt.Store(time.Now().UnixNano())

	q, ok := parseQuery(packet)
	if !ok {
		s.malformed.Add(1)
		// 报文太短连头部都不完整：无从构造应答，静默丢弃。
		// 头部完整但 question 畸形：按规范答 FORMERR（QDCOUNT 置 0）。
		if len(packet) < headerSize {
			return
		}
		_ = respondFormerr(conn, remote, packet)
		return
	}

	// 仅应答标准查询；应答包（QR=1）、非 QUERY opcode 一律静默丢弃。
	if q.flags&flagQR != 0 || q.flags&opcodeMask != opcodeQuery {
		return
	}
	if q.qclass != classIN {
		_ = respondRefused(conn, remote, q)
		s.refused.Add(1)
		return
	}

	s.countMiss(q.name)

	v := s.view.Load()
	rec, hit := v.Lookup(q.name)
	switch q.qtype {
	case typeA:
		if hit && rec.IP != "" {
			if err := respondA(conn, remote, q, rec.IP, int(v.ttl)); err == nil {
				s.answered.Add(1)
			}
			return
		}
		// 命中但无 IP，或清单外：一律 REFUSED。
		_ = respondRefused(conn, remote, q)
		s.refused.Add(1)
	case typeAAAA:
		// 与 agh.txt 的 AAAA 抑制语义对齐：返回 NODATA。
		if hit {
			if err := respondNodata(conn, remote, q); err == nil {
				s.nodata.Add(1)
			}
			return
		}
		_ = respondRefused(conn, remote, q)
		s.refused.Add(1)
	default:
		// 其他类型只承诺 A/AAAA：命中给 NODATA，未命中 REFUSED。
		if hit {
			if err := respondNodata(conn, remote, q); err == nil {
				s.nodata.Add(1)
			}
			return
		}
		_ = respondRefused(conn, remote, q)
		s.refused.Add(1)
	}
}

// countMiss 对清单外域名做限频日志：时间窗限频（默认 10 秒内最多 1 条）。
func (s *Server) countMiss(name string) {
	if v := s.view.Load(); v != nil {
		if _, hit := v.Lookup(name); hit {
			return
		}
	}
	s.missCount.Add(1)
	now := time.Now().UnixNano()
	last := s.missLastLog.Load()
	// 10 秒内最多打印一次
	if now-last < 10_000_000_000 {
		return
	}
	if !s.missLastLog.CompareAndSwap(last, now) {
		return
	}
	// 走 log 而非 fmt.Printf：main 里的 MultiWriter 会同时送入内存环形缓冲，
	// 这样限频告警也能出现在状态页的「运行日志」面板里。
	log.Printf("[dnsserver] 清单外查询累计 %d 条，最新: %s（请检查 AGH 上游分流规则是否与 domains.json 同步）", s.missCount.Load(), name)
}

// parseQuery 做最小解析。ok=false 表示报文畸形。
func parseQuery(packet []byte) (query, bool) {
	if len(packet) < headerSize {
		return query{}, false
	}
	id := binary.BigEndian.Uint16(packet[0:2])
	flags := binary.BigEndian.Uint16(packet[2:4])
	qdcount := binary.BigEndian.Uint16(packet[4:6])
	if qdcount != 1 {
		return query{}, false
	}

	// 解析 question name
	pos := headerSize
	var q string
	for labels := 0; labels < maxNameLabels; labels++ {
		if pos >= len(packet) {
			return query{}, false
		}
		l := int(packet[pos])
		if l == 0 {
			pos++
			break
		}
		// 压缩指针出现在 question name 中是非法的。
		if l&0xC0 != 0 {
			return query{}, false
		}
		if l > maxLabelBytes {
			return query{}, false
		}
		pos++
		if pos+l > len(packet) {
			return query{}, false
		}
		// 逐段拼接，避免一次分配后还要二次处理
		if q != "" {
			q += "."
		}
		q += string(packet[pos : pos+l])
		pos += l
	}
	q = normalizeName(q)
	if q == "" || len(q) > maxDomainBytes {
		return query{}, false
	}

	if pos+4 > len(packet) {
		return query{}, false
	}
	qtype := binary.BigEndian.Uint16(packet[pos : pos+2])
	qclass := binary.BigEndian.Uint16(packet[pos+2 : pos+4])
	question := make([]byte, pos+4-headerSize)
	copy(question, packet[headerSize:pos+4])

	return query{
		id: id, flags: flags, qtype: qtype, qclass: qclass,
		name: q, question: question,
	}, true
}

// respondFlags 构造应答 flags：QR=1，opcode 与 RD 从查询复制，RA=0，rcode 由参数给。
func respondFlags(q query, rcode int) uint16 {
	return flagQR | (q.flags & opcodeMask) | (q.flags & flagRD) | (uint16(rcode) & rcodeMask)
}

// writeHeader 写 12 字节头部。qdcount 通常为 1，FORMERR 时为 0。
func writeHeader(out []byte, q query, rcode, qdcount int) {
	binary.BigEndian.PutUint16(out[0:2], q.id)
	binary.BigEndian.PutUint16(out[2:4], respondFlags(q, rcode))
	binary.BigEndian.PutUint16(out[4:6], uint16(qdcount))
	binary.BigEndian.PutUint16(out[6:8], 0)   // ANCOUNT 由调用方补
	binary.BigEndian.PutUint16(out[8:10], 0)  // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0) // ARCOUNT：不回显 EDNS OPT，合法且 AGH 兼容
}

// respondA 应答一条 A 记录，name 用压缩指针 0xC00C 指向偏移 12 的 question name。
func respondA(conn *net.UDPConn, remote *net.UDPAddr, q query, ip string, ttl int) error {
	ip4 := net.ParseIP(ip).To4()
	if ip4 == nil {
		return fmt.Errorf("非法 IPv4 地址: %q", ip)
	}
	if ttl < 0 {
		ttl = 0
	}
	out := make([]byte, headerSize+len(q.question)+2+10+4)
	writeHeader(out, q, rcodeNoError, 1)
	binary.BigEndian.PutUint16(out[6:8], 1) // ANCOUNT = 1
	copy(out[headerSize:], q.question)
	off := headerSize + len(q.question)
	binary.BigEndian.PutUint16(out[off:off+2], 0xC00C) // 压缩指针
	binary.BigEndian.PutUint16(out[off+2:off+4], typeA)
	binary.BigEndian.PutUint16(out[off+4:off+6], classIN)
	binary.BigEndian.PutUint32(out[off+6:off+10], uint32(ttl))
	binary.BigEndian.PutUint16(out[off+10:off+12], 4) // RDLENGTH
	copy(out[off+12:off+16], ip4)
	_, err := conn.WriteToUDP(out, remote)
	return err
}

// respondNodata 应答 NOERROR + 0 条记录（NODATA）。
func respondNodata(conn *net.UDPConn, remote *net.UDPAddr, q query) error {
	out := make([]byte, headerSize+len(q.question))
	writeHeader(out, q, rcodeNoError, 1)
	copy(out[headerSize:], q.question)
	_, err := conn.WriteToUDP(out, remote)
	return err
}

// respondRefused 应答 REFUSED。
func respondRefused(conn *net.UDPConn, remote *net.UDPAddr, q query) error {
	out := make([]byte, headerSize+len(q.question))
	writeHeader(out, q, rcodeRefused, 1)
	copy(out[headerSize:], q.question)
	_, err := conn.WriteToUDP(out, remote)
	return err
}

// respondFormerr 应答 FORMERR。此时 question 本身可能无效，
// 按规范 QDCOUNT 置 0 且不回显 question。
func respondFormerr(conn *net.UDPConn, remote *net.UDPAddr, packet []byte) error {
	id := uint16(0)
	flags := uint16(rcodeFormErr)
	if len(packet) >= headerSize {
		id = binary.BigEndian.Uint16(packet[0:2])
		qf := binary.BigEndian.Uint16(packet[2:4])
		// 尽量保留 opcode 与 RD，但 RA=0；QR=1。
		flags = flagQR | (qf & opcodeMask) | (qf & flagRD) | (uint16(rcodeFormErr) & rcodeMask)
	}
	out := make([]byte, headerSize)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 0) // QDCOUNT = 0
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	_, err := conn.WriteToUDP(out, remote)
	return err
}

// EncodeQuery 供测试构造查询报文：A / AAAA / 清单外 / 畸形各一。
func EncodeQuery(name string, qtype uint16) []byte {
	labels := strings.Split(normalizeName(name), ".")
	body := make([]byte, 0, 64)
	for _, l := range labels {
		if l == "" {
			continue
		}
		body = append(body, byte(len(l)))
		body = append(body, []byte(l)...)
	}
	body = append(body, 0)
	out := make([]byte, headerSize+4+len(body))
	binary.BigEndian.PutUint16(out[0:2], 0x1234)
	binary.BigEndian.PutUint16(out[2:4], flagRD)
	binary.BigEndian.PutUint16(out[4:6], 1)
	copy(out[headerSize:], body)
	binary.BigEndian.PutUint16(out[headerSize+len(body):headerSize+len(body)+2], qtype)
	binary.BigEndian.PutUint16(out[headerSize+len(body)+2:headerSize+len(body)+4], classIN)
	return out
}
