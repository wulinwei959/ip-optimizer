// Package dnsquery 用纯标准库手写 DNS 报文，向多个上游查询 A 记录。
// 不依赖 miekg/dns 等第三方库，也不需要系统 resolver（避免与 AdGuard Home 形成循环依赖）。
package dnsquery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

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

func queryOne(ctx context.Context, server, name string, timeout time.Duration) ([]net.IP, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	q, err := buildQuery(id, name)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
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

// Collect 并发查询所有上游，返回去重后的候选 IPv4 列表（按地址排序，保证顺序稳定）。
// allowPrivate=false 时过滤 RFC1918；limit 限制单域名候选数，避免扫描量失控。
func Collect(ctx context.Context, name string, servers []string, timeout time.Duration, allowPrivate bool, limit int) ([]string, error) {
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
			ips, err := queryOne(sub, server, name, timeout)
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
			if !usable(ip, allowPrivate) {
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
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
