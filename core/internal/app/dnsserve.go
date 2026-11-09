package app

import (
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

// applyDNSSnapshot 用最新快照构建应答视图并原子替换。
// IP 为空字符串表示「命中但无可用 IP」，应答器会答 REFUSED。
func (a *App) applyDNSSnapshot(snap *output.Snapshot) {
	if a.dnsSrv == nil || snap == nil {
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
	a.dnsSrv.SetView(dnsserver.NewView(recs, ttl))
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

// aghUpstreamLine 生成可直接粘贴到 AGH「上游 DNS 服务器」的分流行。
func (a *App) aghUpstreamLine() string {
	families := a.dnsFamiliesSnapshot()
	if a.dnsSrv == nil || a.dnsListen == "" || len(families) == 0 {
		return ""
	}
	// AGH 语法：[/域名/域名/]主机:端口
	host, port, err := net.SplitHostPort(a.dnsListen)
	if err != nil {
		return ""
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return "[/" + strings.Join(families, "/") + "/]" + host + ":" + port
}

// dnsStatusJSON 组装 /api/dns 的返回内容。
func (a *App) dnsStatusJSON() map[string]any {
	st := a.dnsSrv.Stats()
	resp := map[string]any{
		"ok":        true,
		"enabled":   a.dnsSrv != nil,
		"listen":    a.dnsListen,
		"addr":      a.dnsSrv.Addr(),
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
	if a.dnsSrv == nil {
		resp["hint"] = "DNS 应答器未启用：在 domains.json 的 defaults.dns.listen 填写监听地址（如 127.0.0.1:18053）后重启服务"
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
