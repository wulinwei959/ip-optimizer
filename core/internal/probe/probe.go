// Package probe 对每个候选 IP 做 TCP 测速与 TLS/SNI 证书校验。
// TCP 能连上只证明端口开着；必须完成 TLS 握手且证书链/hostname 都校验通过，
// 才能证明该 IP 真的承载目标域名。这是淘汰「污染 IP / CDN 错位 IP」的关键。
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

// measureTCP 连续建立 Rounds 次连接取中位数；任一次失败即淘汰该 IP。
func (c *Checker) measureTCP(ctx context.Context, addr string) (time.Duration, error) {
	samples := make([]time.Duration, 0, c.opts.Rounds)
	for i := 0; i < c.opts.Rounds; i++ {
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: c.opts.Timeout}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return 0, err
		}
		samples = append(samples, time.Since(start))
		_ = conn.Close()
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[len(samples)/2], nil
}

// verifyTLS 完成 TLS 握手（含证书链与 SNI hostname 校验），可选再校验 HTTP 状态。
func (c *Checker) verifyTLS(ctx context.Context, addr string) (int, error) {
	conn, err := (&net.Dialer{Timeout: c.opts.Timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	tc := tls.Client(conn, &tls.Config{
		ServerName:         c.opts.SNI,
		RootCAs:            c.opts.RootCAs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false, // 必须为 false：证书链 + hostname 校验是核心区分力
	})
	_ = tc.SetDeadline(time.Now().Add(c.opts.Timeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		return 0, fmt.Errorf("TLS/SNI 校验失败: %w", err)
	}
	state := tc.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return 0, fmt.Errorf("证书链未验证（SNI=%s）", c.opts.SNI)
	}
	if len(c.opts.ExpectStatus) == 0 {
		return 0, nil
	}

	// 可选增强：确认服务真的以预期状态应答，避免「证书对但服务不对」。
	// 默认关闭（ExpectStatus 为空），因为部分站点对根路径请求会返回 403/404 导致误杀。
	if _, err := fmt.Fprintf(tc,
		"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: hosts-optimizer/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		c.opts.SNI); err != nil {
		return 0, err
	}
	line, err := bufio.NewReader(tc).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("读取 HTTP 状态行失败: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("非法 HTTP 状态行: %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("非法 HTTP 状态码: %q", fields[1])
	}
	for _, want := range c.opts.ExpectStatus {
		if code == want {
			return code, nil
		}
	}
	return code, fmt.Errorf("HTTP 状态 %d 不在允许列表 %v", code, c.opts.ExpectStatus)
}

// Check 校验单个 IP，失败即返回 error（该 IP 被淘汰）。
func (c *Checker) Check(ctx context.Context, ip string) (Result, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(c.opts.Port))
	lat, err := c.measureTCP(ctx, addr)
	if err != nil {
		return Result{}, err
	}
	status, err := c.verifyTLS(ctx, addr)
	if err != nil {
		return Result{}, err
	}
	return Result{
		IP:         ip,
		LatencyMS:  float64(lat.Microseconds()) / 1000.0,
		TLSChecked: true,
		HTTPStatus: status,
	}, nil
}

// ProbeAll 并发校验所有候选，返回按延迟升序排列的「通过校验」结果。
func ProbeAll(ctx context.Context, ips []string, c *Checker, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
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
