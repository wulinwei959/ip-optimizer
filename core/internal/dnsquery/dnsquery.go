// Package dnsquery 用纯标准库手写 DNS 报文，向多个上游查询 A 记录。
// 不依赖 miekg/dns 等第三方库，也不需要系统 resolver（避免与 AdGuard Home 形成循环依赖）。
package dnsquery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// upstream 描述一个 DNS 上游，kind 为 udp / dot / doh。
type upstream struct {
	kind string
	addr string // udp/dot 的 host:port
	host string // TLS SNI 或 DoH 主机名
	url  string // DoH 完整地址
}

// Options 控制采集行为。
type Options struct {
	Timeout      time.Duration
	AllowPrivate bool
	Limit        int
	RootCAs      *x509.CertPool // DoT/DoH 校验用；nil 表示系统证书池
}

func buildQuery(id uint16, name string) ([]byte, error) {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, id)
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD=1
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // QDCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // ANCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // NSCOUNT
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // ARCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("非法域名标签: %q", label)
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)                                    // 根标签
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // QTYPE=A
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // QCLASS=IN
	return b.Bytes(), nil
}

// skipName 跳过一个域名，支持 0xC0xx 压缩指针。
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, io.ErrUnexpectedEOF
		}
		l := int(msg[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return 0, io.ErrUnexpectedEOF
			}
			return off + 2, nil
		}
		if l > 63 {
			return 0, errors.New("DNS 报文 label 长度非法")
		}
		off += 1 + l
	}
}

func parseAResponse(msg []byte, wantID uint16) ([]net.IP, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS 响应过短")
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != wantID {
		return nil, errors.New("DNS 响应 ID 不匹配")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("收到的不是 DNS 响应")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return nil, fmt.Errorf("DNS rcode=%d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next + 4
		if off > len(msg) {
			return nil, io.ErrUnexpectedEOF
		}
	}
	var ips []net.IP
	for i := 0; i < an; i++ {
		next, err := skipName(msg, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(msg) {
			return nil, io.ErrUnexpectedEOF
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		class := binary.BigEndian.Uint16(msg[off+2 : off+4])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		start := off + 10
		if start+rdlen > len(msg) {
			return nil, io.ErrUnexpectedEOF
		}
		if typ == 1 && class == 1 && rdlen == 4 {
			ips = append(ips, net.IPv4(msg[start], msg[start+1], msg[start+2], msg[start+3]))
		}
		off = start + rdlen
	}
	return ips, nil
}

// ValidateServer 校验单个上游地址写法，供配置校验使用。
func ValidateServer(raw string) error {
	_, err := parseServer(raw)
	return err
}

func splitHostPortDefault(hostport, defPort string) (string, string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", "", errors.New("DNS 地址缺少主机名")
	}
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		if h == "" || p == "" {
			return "", "", fmt.Errorf("DNS 地址缺少主机或端口: %q", hostport)
		}
		return h, p, nil
	}
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), defPort, nil
	}
	return hostport, defPort, nil
}

// parseServer 解析上游地址：
//
//	223.5.5.5                      -> UDP 53
//	223.5.5.5:5353 / udp://...     -> UDP 指定端口
//	tls://dns.alidns.com[:853]     -> DoT
//	https://dns.alidns.com/dns-query -> DoH
func parseServer(raw string) (upstream, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return upstream{}, errors.New("DNS 地址不能为空")
	}
	if !strings.Contains(s, "://") {
		if ip := net.ParseIP(s); ip != nil {
			return upstream{kind: "udp", addr: net.JoinHostPort(s, "53"), host: s}, nil
		}
		if h, p, err := net.SplitHostPort(s); err == nil {
			if net.ParseIP(h) == nil {
				return upstream{}, fmt.Errorf("UDP DNS 必须是字面 IP: %q", s)
			}
			return upstream{kind: "udp", addr: net.JoinHostPort(h, p), host: h}, nil
		}
		return upstream{}, fmt.Errorf("无法识别的 DNS 地址 %q：UDP 用 IP，加密 DNS 用 tls:// 或 https://", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return upstream{}, fmt.Errorf("解析 DNS 地址 %q 失败: %w", s, err)
	}
	if u.Host == "" {
		return upstream{}, fmt.Errorf("DNS 地址 %q 缺少主机名", s)
	}
	switch strings.ToLower(u.Scheme) {
	case "udp", "dns":
		h, p, err := splitHostPortDefault(u.Host, "53")
		if err != nil {
			return upstream{}, err
		}
		if net.ParseIP(h) == nil {
			return upstream{}, fmt.Errorf("UDP DNS 必须是字面 IP: %q", h)
		}
		return upstream{kind: "udp", addr: net.JoinHostPort(h, p), host: h}, nil
	case "tls", "dot":
		h, p, err := splitHostPortDefault(u.Host, "853")
		if err != nil {
			return upstream{}, err
		}
		return upstream{kind: "dot", addr: net.JoinHostPort(h, p), host: h}, nil
	case "https":
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		return upstream{kind: "doh", host: u.Hostname(), url: u.String()}, nil
	case "http":
		return upstream{}, errors.New("DoH 必须使用 https://")
	case "quic", "doq":
		return upstream{}, errors.New("暂不支持 DoQ：QUIC 需要第三方库，本项目仅使用 Go 标准库")
	default:
		return upstream{}, fmt.Errorf("不支持的 DNS 协议 %q（可用：udp、tls、dot、https）", u.Scheme)
	}
}

func newQuery(name string) (uint16, []byte, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	q, err := buildQuery(id, name)
	if err != nil {
		return 0, nil, err
	}
	return id, q, nil
}

func queryUDP(ctx context.Context, up upstream, name string, timeout time.Duration) ([]net.IP, error) {
	id, q, err := newQuery(name)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", up.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseAResponse(buf[:n], id)
}

func queryDoT(ctx context.Context, up upstream, name string, timeout time.Duration, roots *x509.CertPool) ([]net.IP, error) {
	id, q, err := newQuery(name)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", up.addr)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))
	conn := tls.Client(raw, &tls.Config{
		ServerName: up.host, RootCAs: roots, MinVersion: tls.VersionTLS12,
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 {
		return nil, errors.New("DoT 响应长度非法")
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return parseAResponse(resp, id)
}

func queryDoH(ctx context.Context, up upstream, name string, timeout time.Duration, roots *x509.CertPool) ([]net.IP, error) {
	id, q, err := newQuery(name)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		IdleConnTimeout:       timeout,
	}
	client := &http.Client{Transport: transport, Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, up.url, bytes.NewReader(q))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH 返回 HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	return parseAResponse(body, id)
}

func queryOne(ctx context.Context, raw, name string, timeout time.Duration, roots *x509.CertPool) ([]net.IP, error) {
	up, err := parseServer(raw)
	if err != nil {
		return nil, err
	}
	switch up.kind {
	case "dot":
		return queryDoT(ctx, up, name, timeout, roots)
	case "doh":
		return queryDoH(ctx, up, name, timeout, roots)
	default:
		return queryUDP(ctx, up, name, timeout)
	}
}

// usable 淘汰污染/保留地址：回环、私有段、链路本地、组播、文档用保留段、CGNAT。
func usable(ip net.IP, allowPrivate bool) bool {
	b := ip.To4()
	if b == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if b[0] == 0 || b[0] >= 240 {
		return false
	}
	if b[0] == 100 && b[1] >= 64 && b[1] <= 127 { // 100.64.0.0/10 CGNAT
		return false
	}
	if b[0] == 192 && b[1] == 0 && b[2] == 2 { // TEST-NET-1
		return false
	}
	if b[0] == 198 && (b[1] == 18 || b[1] == 19) { // 基准测试段
		return false
	}
	if b[0] == 198 && b[1] == 51 && b[2] == 100 { // TEST-NET-2
		return false
	}
	if b[0] == 203 && b[1] == 0 && b[2] == 113 { // TEST-NET-3
		return false
	}
	if !allowPrivate && ip.IsPrivate() {
		return false
	}
	return true
}

// Collect 保持原有签名，等价于用默认 Options 调用 CollectWithOptions。
func Collect(ctx context.Context, name string, servers []string, timeout time.Duration, allowPrivate bool, limit int) ([]string, error) {
	return CollectWithOptions(ctx, name, servers, Options{
		Timeout: timeout, AllowPrivate: allowPrivate, Limit: limit,
	})
}

// CollectWithOptions 并发查询所有上游（UDP/DoT/DoH），返回去重后的候选 IPv4 列表
// （按地址排序，保证顺序稳定）。allowPrivate=false 时过滤 RFC1918；
// Limit 限制单域名候选数，避免扫描量失控。
func CollectWithOptions(ctx context.Context, name string, servers []string, opts Options) ([]string, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	type answer struct {
		ips []net.IP
		err error
	}
	ch := make(chan answer, len(servers))
	var wg sync.WaitGroup
	for _, s := range servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			sub, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			ips, err := queryOne(sub, server, name, timeout, opts.RootCAs)
			ch <- answer{ips: ips, err: err}
		}(s)
	}
	wg.Wait()
	close(ch)

	seen := make(map[string]bool)
	var out []string
	var lastErr error
	var anySuccess bool
	for a := range ch {
		if a.err != nil {
			lastErr = a.err
			continue
		}
		anySuccess = true
		for _, ip := range a.ips {
			if !usable(ip, opts.AllowPrivate) {
				continue
			}
			key := ip.String()
			if !seen[key] {
				seen[key] = true
				out = append(out, key)
			}
		}
	}
	if !anySuccess {
		if lastErr == nil {
			lastErr = errors.New("无 DNS 上游响应")
		}
		return nil, lastErr
	}
	sort.Strings(out)
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}
