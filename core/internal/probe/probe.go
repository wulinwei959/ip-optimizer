// Package probe 对每个候选 IP 做 TCP 测速与 TLS/SNI 证书校验。
//
// TCP 能连上只证明端口开着；必须完成 TLS 握手且证书链/hostname 都校验通过，
// 才能证明该 IP 真的承载目标域名。这是淘汰「污染 IP / CDN 错位 IP」的关键。
//
// 时延取「TCP 建连 + TLS 握手」多次取样的中位数，而不是只看 TCP 建连：
// 建连快但握手慢（或服务不对）的 IP 正是最容易被误选的一类，
// 而且 TLS 握手才是用户首个请求真正付出的往返成本。
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Result 是一个通过全部校验的候选 IP。
type Result struct {
	IP         string
	LatencyMS  float64
	TLSChecked bool
	HTTPStatus int
}

// Options 是单个域名的探测参数。
type Options struct {
	SNI          string
	Port         int
	Rounds       int
	Timeout      time.Duration
	RootCAs      *x509.CertPool
	ExpectStatus []int
}

// Checker 校验一组 IP 是否承载指定 SNI。
type Checker struct {
	opts Options
}

func New(o Options) *Checker {
	if o.Rounds < 1 {
		o.Rounds = 1
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	return &Checker{opts: o}
}

// dial 建立 TCP 连接并返回建连耗时。
func (c *Checker) dial(ctx context.Context, addr string) (net.Conn, time.Duration, error) {
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: c.opts.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	return conn, time.Since(start), nil
}

// handshake 在已建立的连接上完成 TLS 握手（含证书链与 SNI 校验），
// 可选再校验 HTTP 状态码。返回握手耗时与状态码。
func (c *Checker) handshake(ctx context.Context, conn net.Conn, addr string) (time.Duration, int, error) {
	start := time.Now()
	tc := tls.Client(conn, &tls.Config{
		ServerName: c.opts.SNI,
		RootCAs:    c.opts.RootCAs,
		MinVersion: tls.VersionTLS12,
		// 必须为 false：证书链 + hostname 校验是核心区分力
	})
	_ = tc.SetDeadline(time.Now().Add(c.opts.Timeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		return 0, 0, fmt.Errorf("TLS/SNI 校验失败: %w", err)
	}
	state := tc.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return 0, 0, fmt.Errorf("证书链未验证（SNI=%s）", c.opts.SNI)
	}
	if len(c.opts.ExpectStatus) == 0 {
		return time.Since(start), 0, nil
	}

	// 可选增强：确认服务真的以预期状态应答，避免「证书对但服务不对」。
	// 默认关闭（ExpectStatus 为空），因为部分站点对根路径请求会返回 403/404 导致误杀。
	if _, err := fmt.Fprintf(tc,
		"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: hosts-optimizer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		c.opts.SNI); err != nil {
		return 0, 0, err
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		return 0, 0, fmt.Errorf("读取 HTTP 状态行失败: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("非法 HTTP 状态行: %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("非法 HTTP 状态码: %q", fields[1])
	}
	for _, want := range c.opts.ExpectStatus {
		if code == want {
			return time.Since(start), code, nil
		}
	}
	return 0, code, fmt.Errorf("HTTP 状态 %d 不在允许列表 %v", code, c.opts.ExpectStatus)
}

// Check 校验单个 IP，失败即返回 error（该 IP 被淘汰）。
func (c *Checker) Check(ctx context.Context, ip string) (Result, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(c.opts.Port))
	samples := make([]time.Duration, 0, c.opts.Rounds)
	status := 0
	for i := 0; i < c.opts.Rounds; i++ {
		conn, tcpMS, err := c.dial(ctx, addr)
		if err != nil {
			return Result{}, err
		}
		hsMS, st, err := c.handshake(ctx, conn, addr)
		_ = conn.Close()
		if err != nil {
			return Result{}, err
		}
		samples = append(samples, tcpMS+hsMS)
		status = st
	}
	return Result{
		IP:         ip,
		LatencyMS:  float64(median(samples).Microseconds()) / 1000.0,
		TLSChecked: true,
		HTTPStatus: status,
	}, nil
}

// median 返回耗时切片的中位数（偶数个取中间两个的平均）。
func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// ProbeAll 并发校验所有候选，返回按延迟升序排列的「通过校验」结果。
//
// sem 由调用方提供，整轮（跨域名）共用一个池：否则某个域名会吃满并发额度，
// 其他域名只能串行干等。sem 为 nil 时退化为内部自建池（兼容单测直接调用）。
func ProbeAll(ctx context.Context, ips []string, c *Checker, sem chan struct{}) []Result {
	if sem == nil {
		sem = make(chan struct{}, 16)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []Result
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			r, err := c.Check(ctx, ip)
			if err != nil {
				return
			}
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].LatencyMS < out[j].LatencyMS })
	return out
}
