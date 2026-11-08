package dnsserver

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestViewLookup 验证视图的精确匹配、父域回退、无命中与空 IP 语义。
func TestViewLookup(t *testing.T) {
	v := NewView([]Record{
		{Name: "github.com", IP: "1.1.1.1"},
		{Name: "raw.githubusercontent.com", IP: "2.2.2.2"},
		{Name: "disabled.com", IP: ""}, // 命中但无可用 IP
	}, 60)

	// 精确命中
	if rec, ok := v.Lookup("github.com"); !ok || rec.IP != "1.1.1.1" {
		t.Fatalf("精确命中失败: %+v %v", rec, ok)
	}
	// 父域回退：api.github.com 未显式配置，应回退命中 github.com 规则
	if rec, ok := v.Lookup("api.github.com"); !ok || rec.IP != "1.1.1.1" {
		t.Fatalf("父域回退失败: %+v %v", rec, ok)
	}
	// 尾点与大小写应被规范化后命中
	if rec, ok := v.Lookup("GITHUB.COM."); !ok || rec.IP != "1.1.1.1" {
		t.Fatalf("规范化失败: %+v %v", rec, ok)
	}
	// 命中但 IP 为空：返回记录 + hit=true
	if rec, ok := v.Lookup("disabled.com"); !ok || rec.IP != "" {
		t.Fatalf("空 IP 记录应命中: %+v %v", rec, ok)
	}
	// 清单外
	if _, ok := v.Lookup("baidu.com"); ok {
		t.Fatal("清单外域名不应命中")
	}
	// 后缀不得通配：githubusercontent.com 是独立配置，不是 github.com 的子域
	if _, ok := v.Lookup("githubusercontent.com"); ok {
		t.Fatal("不得做后缀通配")
	}
	// 显式子域优先于父域规则
	if rec, ok := v.Lookup("raw.githubusercontent.com"); !ok || rec.IP != "2.2.2.2" {
		t.Fatalf("显式子域应优先: %+v %v", rec, ok)
	}
}

// TestNilServerSafe 验证所有公开方法对 nil 接收者安全。
func TestNilServerSafe(t *testing.T) {
	var s *Server
	s.SetView(NewView(nil, 60))
	if s.Listen() != "" || s.Addr() != "" || s.Started() {
		t.Fatal("nil 服务器的字符串/状态访问应返回零值")
	}
	if err := s.Serve(context.Background()); err != nil {
		t.Fatalf("nil Serve 应为 no-op: %v", err)
	}
	if st := s.Stats(); st.Queries != 0 || st.Started {
		t.Fatalf("nil Stats 应为零值: %+v", st)
	}
}

// TestNewEmptyListen 验证 listen 为空字符串返回 nil（禁用）。
func TestNewEmptyListen(t *testing.T) {
	if New("") != nil || New("  ") != nil {
		t.Fatal("空 listen 应返回 nil")
	}
	if New("127.0.0.1:0") == nil {
		t.Fatal("合法 listen 应返回非 nil")
	}
}

// TestUDPEndToEnd 覆盖语义矩阵：A 命中 / 父域回退 / AAAA NODATA /
// 无 IP REFUSED / 清单外 REFUSED / 运行计数。
func TestUDPEndToEnd(t *testing.T) {
	view := NewView([]Record{
		{Name: "github.com", IP: "1.2.3.4"},
		{Name: "disabled.com", IP: ""},
	}, 60)

	s := New("127.0.0.1:0")
	s.SetView(view)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()
	waitStarted(t, s)

	// A 命中：NOERROR + 1 条 A，TTL 60，RDATA 为配置 IP
	resp := roundtrip(t, s, EncodeQuery("github.com", typeA))
	if rcode(resp) != rcodeNoError {
		t.Fatalf("A 命中应 NOERROR，实际 rcode=%d", rcode(resp))
	}
	if an := ancount(resp); an != 1 {
		t.Fatalf("A 命中应答数应为 1，实际 %d", an)
	}
	if ip, ttl := answerA(resp); ip != "1.2.3.4" || ttl != 60 {
		t.Fatalf("A 应答内容不符: ip=%s ttl=%d", ip, ttl)
	}

	// A 命中（父域回退）：raw.github.com 命中 github.com 规则
	resp = roundtrip(t, s, EncodeQuery("raw.github.com", typeA))
	if ip, _ := answerA(resp); ip != "1.2.3.4" {
		t.Fatalf("父域回退应答 IP 应为 1.2.3.4，实际 %s", ip)
	}

	// AAAA 命中：NODATA
	resp = roundtrip(t, s, EncodeQuery("github.com", typeAAAA))
	if rcode(resp) != rcodeNoError {
		t.Fatalf("AAAA 命中应 NOERROR，实际 rcode=%d", rcode(resp))
	}
	if an := ancount(resp); an != 0 {
		t.Fatalf("AAAA 命中应 NODATA，实际 an=%d", an)
	}

	// 清单外：REFUSED
	resp = roundtrip(t, s, EncodeQuery("baidu.com", typeA))
	if rcode(resp) != rcodeRefused {
		t.Fatalf("清单外应 REFUSED，实际 rcode=%d", rcode(resp))
	}

	// 命中但无 IP：REFUSED（失败不覆盖原则）
	resp = roundtrip(t, s, EncodeQuery("disabled.com", typeA))
	if rcode(resp) != rcodeRefused {
		t.Fatalf("无 IP 应 REFUSED，实际 rcode=%d", rcode(resp))
	}

	// 非 IN 类：REFUSED
	resp = roundtrip(t, s, encodeQueryClass("github.com", typeA, 3))
	if rcode(resp) != rcodeRefused {
		t.Fatalf("非 IN 类应 REFUSED，实际 rcode=%d", rcode(resp))
	}

	st := s.Stats()
	if st.Queries == 0 || st.Answered == 0 || st.Nodata == 0 || st.Refused == 0 {
		t.Fatalf("运行计数不全: %+v", st)
	}
}

// TestMalformedDoesNotKill 循环发畸形包，进程应存活、malformed 计数增长。
func TestMalformedDoesNotKill(t *testing.T) {
	s := New("127.0.0.1:0")
	s.SetView(NewView([]Record{{Name: "a.com", IP: "1.1.1.1"}}, 60))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()
	waitStarted(t, s)

	// 混合四类输入，均不得 panic 或拖死进程。
	junk := [][]byte{
		{0x01, 0x02, 0x03}, // 短于头部
		encodeMalformed(),  // QDCOUNT=2
		append(make([]byte, headerSize), 0x01, 0x41), // question 截断
		make([]byte, 4096),                           // 全零大包
	}
	for i := 0; i < 40; i++ {
		for _, p := range junk {
			roundtripRaw(t, s, p)
		}
	}
	if s.Stats().Malformed == 0 {
		t.Fatal("畸形计数应增长")
	}
}

// TestMissCountsAsRefused 验证清单外查询计入 refused。
func TestMissCountsAsRefused(t *testing.T) {
	s := New("127.0.0.1:0")
	s.SetView(NewView([]Record{{Name: "a.com", IP: "1.1.1.1"}}, 60))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()
	waitStarted(t, s)
	for i := 0; i < 5; i++ {
		roundtrip(t, s, EncodeQuery("out.com", typeA))
	}
	if s.Stats().Refused < 5 {
		t.Fatalf("清单外查询应计入 refused: %+v", s.Stats())
	}
}

// TestSetViewSwap 验证视图可被原子替换，替换后立即按新视图应答。
func TestSetViewSwap(t *testing.T) {
	s := New("127.0.0.1:0")
	s.SetView(NewView([]Record{{Name: "a.com", IP: "1.1.1.1"}}, 60))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()
	waitStarted(t, s)

	if ip, _ := answerA(roundtrip(t, s, EncodeQuery("a.com", typeA))); ip != "1.1.1.1" {
		t.Fatalf("初始视图应答不符: %s", ip)
	}
	// 替换 IP
	s.SetView(NewView([]Record{{Name: "a.com", IP: "9.9.9.9"}}, 30))
	if ip, ttl := answerA(roundtrip(t, s, EncodeQuery("a.com", typeA))); ip != "9.9.9.9" || ttl != 30 {
		t.Fatalf("视图替换后应答不符: ip=%s ttl=%d", ip, ttl)
	}
	// 替换为空视图 → REFUSED
	s.SetView(NewView(nil, 60))
	if r := rcode(roundtrip(t, s, EncodeQuery("a.com", typeA))); r != rcodeRefused {
		t.Fatalf("空视图应 REFUSED，实际 rcode=%d", r)
	}
}

func waitStarted(t *testing.T, s *Server) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if s.Stats().Started {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("服务未启动")
}

// encodeMalformed 构造「头部完整但 QDCOUNT=2」的畸形查询，应得 FORMERR。
func encodeMalformed() []byte {
	out := make([]byte, headerSize+4)
	binary.BigEndian.PutUint16(out[0:2], 0x1234)
	binary.BigEndian.PutUint16(out[2:4], flagRD)
	binary.BigEndian.PutUint16(out[4:6], 2) // 非法 QDCOUNT
	out = append(out[12:], 0, 0, 1, 1)
	return out
}

// encodeQueryClass 构造指定 QCLASS 的查询，用于验证非 IN 类被拒绝。
func encodeQueryClass(name string, qtype, qclass uint16) []byte {
	q := EncodeQuery(name, qtype)
	binary.BigEndian.PutUint16(q[len(q)-2:], qclass)
	return q
}

func roundtrip(t *testing.T, s *Server, query []byte) []byte {
	t.Helper()
	return roundtripRaw(t, s, query)
}

func roundtripRaw(t *testing.T, s *Server, query []byte) []byte {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", s.Addr())
	if err != nil {
		t.Fatalf("解析地址失败: %v", err)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		t.Fatalf("设置超时失败: %v", err)
	}
	if _, err := conn.Write(query); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	buf := make([]byte, maxUDPSize)
	n, err := conn.Read(buf)
	if err != nil {
		// 被静默丢弃的查询没有应答，返回 nil 供调用方判断。
		return nil
	}
	return buf[:n]
}

// rcode 提取应答 RCODE。
func rcode(resp []byte) int {
	if len(resp) < headerSize {
		return -1
	}
	return int(resp[3] & rcodeMask)
}

// ancount 提取应答计数。
func ancount(resp []byte) int {
	if len(resp) < 8 {
		return 0
	}
	return int(resp[6])<<8 | int(resp[7])
}

// answerA 解析应答中的第一条 A 记录，返回 IP 与 TTL。
func answerA(resp []byte) (string, int) {
	if len(resp) < headerSize+16 {
		return "", 0
	}
	off := len(resp) - 16
	if off < headerSize {
		return "", 0
	}
	if name := int(resp[off])<<8 | int(resp[off+1]); name != 0xC00C {
		return "", 0
	}
	if qtype := int(resp[off+2])<<8 | int(resp[off+3]); qtype != typeA {
		return "", 0
	}
	ttl := int(uint32(resp[off+6])<<24 | uint32(resp[off+7])<<16 | uint32(resp[off+8])<<8 | uint32(resp[off+9]))
	return net.IP(resp[off+12 : off+16]).String(), ttl
}
