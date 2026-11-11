package app

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsserver"
	"hosts-optimizer/internal/output"
)

const (
	// 单行分流行最多放多少个域名 / 多少字节，超出就换行。
	// AGH 的上游服务器列表是逐行解析的，拆多行不影响语义。
	maxDomainsPerLine = 40
	maxAghLineBytes   = 2000
)

// initDNSServer 根据配置初始化内置 DNS 应答器。
// 必须在 recoverSnapshot 之前调用：恢复流程会刷新应答视图，依赖 dnsSrv 已就绪。
// 同时在这里设定 TTL 初值，避免首轮探测前恢复出的视图带 TTL=0。
func (a *App) initDNSServer(rt *config.Runtime) {
	d := rt.Config.Defaults.DNS
	a.dnsTTL.Store(int64(d.TTL))
	if strings.TrimSpace(d.Listen) == "" {
		a.dnsListen = ""
		log.Printf("DNS 应答器已禁用（dns.listen 为空）")
		return
	}
	a.dnsSrv = dnsserver.New(d.Listen)
	a.dnsListen = d.Listen
	a.updateDNSFamilies(rt.Config.Domains)
	log.Printf("DNS 应答器就绪：监听 %s，TTL %d 秒", d.Listen, d.TTL)
}

// startDNSServerLocked 在已持有 dnsMu 写锁的前提下启动监听 goroutine。
func (a *App) startDNSServerLocked() {
	if a.dnsSrv == nil || a.dnsListen == "" {
		return
	}
	base := a.dnsBaseCtx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	done := make(chan struct{})
	srv := a.dnsSrv
	a.dnsCancel = cancel
	a.dnsDone = done
	go func() {
		defer close(done)
		if err := srv.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) && a.errCh != nil {
			a.errCh <- err
		}
	}()
}

// stopDNSServerLocked 在已持有 dnsMu 写锁的前提下停止监听并等待端口释放。
// 必须等旧 socket 真正关闭，否则同一端口改绑 0.0.0.0 会撞 EADDRINUSE。
func (a *App) stopDNSServerLocked() {
	if a.dnsCancel == nil {
		return
	}
	a.dnsCancel()
	if a.dnsDone != nil {
		select {
		case <-a.dnsDone:
		case <-time.After(3 * time.Second):
			log.Printf("DNS 应答器停止超时，继续切换监听地址")
		}
	}
	a.dnsCancel = nil
	a.dnsDone = nil
}

// ensureDNSServerStarted 在 Run 启动时拉起应答器（此时才拿到根 ctx 与 errCh）。
func (a *App) ensureDNSServerStarted() {
	a.dnsMu.Lock()
	defer a.dnsMu.Unlock()
	if a.dnsSrv == nil || a.dnsCancel != nil {
		return
	}
	a.startDNSServerLocked()
}

// applyDNSListen 让 domains.json 的 dns.listen 在下一轮探测时热生效。
// 监听地址变更需要重绑端口，仅改字段是不生效的。
func (a *App) applyDNSListen(raw string) {
	listen := strings.TrimSpace(raw)

	a.dnsMu.Lock()
	if listen == a.dnsListen {
		a.dnsMu.Unlock()
		return
	}
	old := a.dnsListen
	oldSrv := a.dnsSrv
	a.stopDNSServerLocked()
	a.dnsListen = listen
	a.dnsSrv = nil

	if listen != "" {
		// 先探测能否绑定：失败则回滚旧监听，绝不出现「配置改了、端口没绑上、
		// 分流行却指向新地址」的脱节状态。
		if err := canBindUDP(listen); err != nil {
			a.dnsListen = old
			a.dnsSrv = oldSrv
			if a.dnsSrv != nil && a.dnsBaseCtx != nil {
				a.startDNSServerLocked()
			}
			a.dnsMu.Unlock()
			log.Printf("DNS 监听地址 %q 不可用（%v），已保留原监听 %q", listen, err, old)
			return
		}
		a.dnsSrv = dnsserver.New(listen)
		if a.dnsSrv != nil && a.dnsBaseCtx != nil {
			a.startDNSServerLocked()
		}
	}
	a.dnsMu.Unlock()

	if listen == "" {
		log.Printf("DNS 应答器已禁用（dns.listen 为空）")
		return
	}
	if a.dnsSrv == nil {
		log.Printf("DNS 应答器监听地址非法，已禁用：%q", listen)
		return
	}
	// 新监听没有视图，立即用当前快照恢复，避免重启瞬间全部 REFUSED。
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	a.applyDNSSnapshot(snap)
	log.Printf("DNS 应答器监听已切换：%q → %q", old, listen)
}

// canBindUDP 预检监听地址是否可绑定，避免热切换时才发现端口被占用。
func canBindUDP(listen string) error {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// dnsServerSnapshot 原子读取当前应答器与监听地址。
func (a *App) dnsServerSnapshot() (*dnsserver.Server, string) {
	a.dnsMu.RLock()
	defer a.dnsMu.RUnlock()
	return a.dnsSrv, a.dnsListen
}

// applyDNSSnapshot 用最新快照构建应答视图并原子替换。
// IP 为空字符串表示「命中但无可用 IP」，应答器会答 REFUSED。
func (a *App) applyDNSSnapshot(snap *output.Snapshot) {
	srv, _ := a.dnsServerSnapshot()
	if srv == nil || snap == nil {
		return
	}
	recs := make([]dnsserver.Record, 0, len(snap.Status.Domains))
	for _, d := range snap.Status.Domains {
		recs = append(recs, dnsserver.Record{Name: d.Name, IP: d.IP})
	}
	ttl := int(a.dnsTTL.Load())
	if ttl <= 0 {
		ttl = 60
	}
	srv.SetView(dnsserver.NewView(recs, ttl))
}

// updateDNSFamilies 刷新「启用域名的完整域名清单」，用于生成 AGH 上游分流行。
// 同时也会被配置写回路径调用，保证禁用/启用即时反映到上游行。
// 注意：这里必须用完整域名而非注册域。AGH 的 ||domain^ 语义匹配该域名及其
// 全部子域，若只列注册域，raw.githubusercontent.com 这类已独立配置的子域会被
// 父域规则劫持，永远拿不到自己的优选 IP。
func (a *App) updateDNSFamilies(domains []config.Domain) {
	set := make(map[string]bool, len(domains))
	for _, d := range domains {
		name := strings.ToLower(strings.TrimSpace(d.Name))
		if name == "" || d.Disabled {
			continue
		}
		set[name] = true
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	// 整体替换指针而非就地写切片：读侧只需一次原子加载即可拿到一致的快照。
	a.dnsFamilies.Store(&out)
}

// dnsFamiliesSnapshot 读取当前家族清单的稳定副本，nil 表示应答器不可用。
func (a *App) dnsFamiliesSnapshot() []string {
	if p := a.dnsFamilies.Load(); p != nil {
		return *p
	}
	return nil
}

// refreshDNSFamiliesFromConfig 重新读取磁盘配置并刷新家族清单。
// 配置写回后调用，失败时保留原清单并告警（不影响主流程）。
func (a *App) refreshDNSFamiliesFromConfig() {
	rt, err := config.Load()
	if err != nil {
		log.Printf("刷新 DNS 家族清单失败（沿用旧清单）: %v", err)
		return
	}
	a.updateDNSFamilies(rt.Config.Domains)
}

// aghUpstreamLine 生成可直接粘贴到 AGH「上游 DNS 服务器」的分流行（多行时用换行连接）。
func (a *App) aghUpstreamLine() string {
	return strings.Join(a.aghUpstreamLines(), "\n")
}

// aghUpstreamLines 生成分流行列表。
//
// AGH 的上游服务器列表本身是逐行解析的，而域名多时单行会非常长（超出配置框/校验限制），
// 因此按「每行域名个数 + 单行字节数」两个上限拆成多行，语义完全不变。
func (a *App) aghUpstreamLines() []string {
	families := a.dnsFamiliesSnapshot()
	srv, listen := a.dnsServerSnapshot()
	if srv == nil || listen == "" || len(families) == 0 {
		return nil
	}
	// 以「实际绑定的地址」为准，保证分流行与监听地址永远同步。
	if addr := srv.Addr(); addr != "" {
		listen = addr
	}
	// AGH 语法：[/域名/域名/]主机:端口
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	// 监听通配地址时，分流行必须换成容器可达的内网 IP，否则 AGH 拿到的是 0.0.0.0。
	if host == "" || isWildcardHost(host) {
		host = outboundHost()
	}
	suffix := "/]" + host + ":" + port

	lines := make([]string, 0, len(families)/maxDomainsPerLine+1)
	cur := ""
	count := 0
	for _, fam := range families {
		seg := fam
		if count > 0 {
			seg = "/" + seg
		}
		if count > 0 && (count >= maxDomainsPerLine || len(cur)+len(seg)+len(suffix) > maxAghLineBytes) {
			lines = append(lines, "[/"+cur+suffix)
			cur, count = "", 0
			seg = fam
		}
		cur += seg
		count++
	}
	if count > 0 {
		lines = append(lines, "[/"+cur+suffix)
	}
	return lines
}

// isWildcardHost 判断是否为 0.0.0.0 / :: 这类通配监听地址。
func isWildcardHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// outboundHost 取本机第一个非回环 IPv4，优先私有地址。
// 用于把 0.0.0.0 监听翻译成 Docker 容器可访问的主机地址。
func outboundHost() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	fallback := ""
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP
		if ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		if ip.IsPrivate() {
			return ip.String()
		}
		if fallback == "" {
			fallback = ip.String()
		}
	}
	if fallback != "" {
		return fallback
	}
	return "127.0.0.1"
}

// dnsStatusJSON 组装 /api/dns 的返回内容。
func (a *App) dnsStatusJSON() map[string]any {
	srv, listen := a.dnsServerSnapshot()
	st := srv.Stats()
	resp := map[string]any{
		"ok":        true,
		"enabled":   srv != nil,
		"listen":    listen,
		"addr":      srv.Addr(),
		"ttl":       int(a.dnsTTL.Load()),
		"queries":   st.Queries,
		"answered":  st.Answered,
		"nodata":    st.Nodata,
		"refused":   st.Refused,
		"malformed": st.Malformed,
	}
	if !st.LastQueryAt.IsZero() {
		resp["last_query_at"] = st.LastQueryAt.Format(time.RFC3339)
	}
	if srv == nil {
		resp["hint"] = "DNS 应答器未启用：在 domains.json 的 defaults.dns.listen 填写监听地址（如 127.0.0.1:18053），保存后点「立即刷新」即可生效"
		return resp
	}
	resp["agh_upstream"] = a.aghUpstreamLine()
	resp["hint"] = "把 agh_upstream 粘贴到 AdGuard Home「设置 → DNS 设置 → 上游 DNS 服务器」末尾；该模式与过滤器订阅二选一"
	return resp
}

// handleDNSStats 返回应答器运行状态与 AGH 分流规则。
func (a *App) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET"})
		return
	}
	writeJSON(w, http.StatusOK, a.dnsStatusJSON())
}
