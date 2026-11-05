// Package app 编排一轮探测、进程内定时、单端口 HTTP 服务与产物落盘。
package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsquery"
	"hosts-optimizer/internal/output"
	"hosts-optimizer/internal/probe"
	"hosts-optimizer/internal/store"
	"hosts-optimizer/internal/util"
)

// App 是长期运行的服务实例。
type App struct {
	port                                      string
	hostsPath, aghPath, statusPath, statePath string
	rootCAs                                   *x509.CertPool
	state                                     *store.State

	mu           sync.RWMutex
	snap         *output.Snapshot
	roundMu      sync.Mutex
	lastSchedule int
}

// New 初始化目录、CA 池、状态，并尝试从磁盘恢复上一轮产物。
func New(rt *config.Runtime) (*App, error) {
	if err := os.MkdirAll(rt.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建产物目录失败: %w", err)
	}
	if err := os.MkdirAll(rt.StateDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建状态目录失败: %w", err)
	}
	pool, err := buildRootCAs(rt.CABundle)
	if err != nil {
		return nil, err
	}
	st, corrupted, err := store.Load(filepath.Join(rt.StateDir, "state.json"))
	if err != nil && !corrupted {
		return nil, err
	}
	if corrupted {
		log.Printf("警告: %v", err)
	}
	a := &App{
		port:         rt.Port,
		hostsPath:    filepath.Join(rt.OutputDir, "hosts.txt"),
		aghPath:      filepath.Join(rt.OutputDir, "agh.txt"),
		statusPath:   filepath.Join(rt.OutputDir, "status.json"),
		statePath:    filepath.Join(rt.StateDir, "state.json"),
		rootCAs:      pool,
		state:        st,
		lastSchedule: rt.Config.Defaults.ScheduleMinutes,
	}
	a.recoverSnapshot()
	return a, nil
}

func buildRootCAs(path string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if path == "" {
		log.Printf("CA 根证书：使用系统证书池（未配置 HO_CA_BUNDLE）")
		return pool, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		// 缺失的 CA bundle 不是致命错误：降级为仅用系统证书池，并告警。
		// 这样即便打包时未携带 ca-bundle.crt，服务也能启动（避免 Restart=always 无限重启）。
		if os.IsNotExist(err) {
			log.Printf("CA 根证书：未找到 %s，已降级为仅用系统证书池", path)
			return pool, nil
		}
		return nil, fmt.Errorf("读取 CA bundle %s 失败: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("%s 未解析出任何根证书", path)
	}
	log.Printf("CA 根证书：系统池 + %s", path)
	return pool, nil
}

// recoverSnapshot 让服务重启后立刻能对外提供上一轮订阅内容，不必等首轮探测结束。
func (a *App) recoverSnapshot() {
	hosts, err1 := os.ReadFile(a.hostsPath)
	agh, err2 := os.ReadFile(a.aghPath)
	if err1 != nil || err2 != nil {
		return
	}
	snap := &output.Snapshot{
		Hosts: hosts, AGH: agh,
		HostsETag: output.ETag(hosts), AGHETag: output.ETag(agh),
		Modified: time.Now(), Ready: true,
	}
	if b, err := os.ReadFile(a.statusPath); err == nil {
		var st output.Status
		if json.Unmarshal(b, &st) == nil {
			snap.StatusBytes, snap.StatusETag, snap.Status = b, output.ETag(b), st
		}
	}
	a.mu.Lock()
	a.snap = snap
	a.mu.Unlock()
	log.Printf("已从磁盘恢复上一轮产物")
}

// Run 启动 HTTP 服务与定时探测循环，直到 ctx 取消。
func (a *App) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handle)
	srv := &http.Server{
		Addr: ":" + a.port, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	log.Printf("HTTP 服务已启动，监听 :%s", a.port)

	for {
		select {
		case err := <-errCh:
			return err
		default:
		}
		minutes, err := a.doRound(ctx)
		if err != nil {
			log.Printf("本轮探测出错: %v", err)
		}
		if minutes < 1 {
			minutes = 1
		}
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
			return nil
		case err := <-errCh:
			return err
		case <-time.After(time.Duration(minutes) * time.Minute):
		}
	}
}

// doRound 执行一轮；roundMu 保证定时器与 /refresh 不会并发探测。
// 每轮重新读取 domains.json，因此手动增删域名后下一轮自动生效，无需重启。
func (a *App) doRound(ctx context.Context) (int, error) {
	a.roundMu.Lock()
	defer a.roundMu.Unlock()

	rt, err := config.Load()
	if err != nil {
		log.Printf("配置加载失败（保留上一轮产物）: %v", err)
		return a.lastSchedule, err
	}
	a.lastSchedule = rt.Config.Defaults.ScheduleMinutes
	d := rt.Config.Defaults
	timeout := time.Duration(d.TimeoutSeconds) * time.Second
	started := time.Now()

	entries := make([]output.Entry, 0, len(rt.Config.Domains))
	for _, dom := range rt.Config.Domains {
		t := rt.Config.Resolve(dom)
		var ips []string
		if len(t.Candidates) > 0 {
			ips = t.Candidates
		} else {
			ips, err = dnsquery.Collect(ctx, t.Name, d.ProbeDNS, timeout, t.AllowPrivate, d.MaxCandidates)
			if err != nil {
				log.Printf("[%s] DNS 采集失败: %v", t.Name, err)
			}
		}
		checker := probe.New(probe.Options{
			SNI: t.SNI, Port: t.Port, Rounds: d.TCPRounds,
			Timeout: timeout, RootCAs: a.rootCAs, ExpectStatus: t.ExpectStatus,
		})
		results := probe.ProbeAll(ctx, ips, checker, d.Concurrency)
		cands := make([]store.Candidate, 0, len(results))
		for _, r := range results {
			cands = append(cands, store.Candidate{IP: r.IP, LatencyMS: r.LatencyMS})
		}
		dec := a.state.Decide(t.Name, cands, d.HysteresisPercent, d.HysteresisRounds, time.Now())
		entries = append(entries, output.Entry{
			Name: t.Name, IP: dec.IP, LatencyMS: dec.LatencyMS,
			Reason: dec.Reason, Validated: dec.Validated,
			Candidates: len(ips), SuppressAAAA: t.SuppressAAAA,
		})
		log.Printf("[%s] 候选 %d → 校验通过 %d → 生效 %q（%s）", t.Name, len(ips), len(results), dec.IP, dec.Reason)
	}

	now := time.Now()
	round := output.RoundInfo{
		StartedAt: started, FinishedAt: now, OK: true,
		ScheduleMinutes: d.ScheduleMinutes,
	}
	if err := a.state.Save(a.statePath, now); err != nil {
		log.Printf("保存状态失败: %v", err)
	}
	snap, err := output.Build(entries, now, round)
	if err != nil {
		return d.ScheduleMinutes, err
	}
	if snap.Ready {
		if err := util.AtomicWrite(a.hostsPath, snap.Hosts); err != nil {
			return d.ScheduleMinutes, err
		}
		if err := util.AtomicWrite(a.aghPath, snap.AGH); err != nil {
			return d.ScheduleMinutes, err
		}
	} else if !util.Exists(a.hostsPath) {
		// 首次启动且还没有任何有效 IP：写仅含注释的文件，让端点可访问。
		// 之后若整轮全灭，走 else 分支保留上一轮产物，绝不覆盖。
		if err := util.AtomicWrite(a.hostsPath, snap.Hosts); err != nil {
			return d.ScheduleMinutes, err
		}
		if err := util.AtomicWrite(a.aghPath, snap.AGH); err != nil {
			return d.ScheduleMinutes, err
		}
	}
	if err := util.AtomicWrite(a.statusPath, snap.StatusBytes); err != nil {
		return d.ScheduleMinutes, err
	}
	a.mu.Lock()
	a.snap = snap
	a.mu.Unlock()
	log.Printf("本轮完成：%d/%d 个域名生效，产物已写入 %s", snap.Status.ActiveCount, len(entries), filepath.Dir(a.hostsPath))
	return d.ScheduleMinutes, nil
}

func (a *App) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		a.index(w, r)
	case "/hosts.txt":
		a.serve(w, r, "hosts")
	case "/agh.txt":
		a.serve(w, r, "agh")
	case "/status.json":
		a.serve(w, r, "status")
	case "/refresh":
		a.refresh(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) serve(w http.ResponseWriter, r *http.Request, kind string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "仅支持 GET / HEAD", http.StatusMethodNotAllowed)
		return
	}
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	if snap == nil {
		http.Error(w, "服务正在初始化，请稍后重试", http.StatusServiceUnavailable)
		return
	}
	var data []byte
	var etag, contentType string
	switch kind {
	case "hosts":
		data, etag, contentType = snap.Hosts, snap.HostsETag, "text/plain; charset=utf-8"
	case "agh":
		data, etag, contentType = snap.AGH, snap.AGHETag, "text/plain; charset=utf-8"
	default:
		data, etag, contentType = snap.StatusBytes, snap.StatusETag, "application/json; charset=utf-8"
	}
	if kind != "status" && !snap.Ready {
		http.Error(w, "尚无有效 IP：请检查 domains.json 的域名/候选，或 POST /refresh 重试；失败时保留上一轮结果", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Last-Modified", snap.Modified.UTC().Format(http.TimeFormat))
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *App) refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "仅支持 POST", http.StatusMethodNotAllowed)
		return
	}
	minutes, err := a.doRound(r.Context())
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "next_round_minutes": minutes})
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>hosts-optimizer</title>
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;line-height:1.6}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;padding:8px;text-align:left;word-break:break-all}
code{background:#f2f2f2;padding:2px 5px;border-radius:4px}
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:16px 0}
button{cursor:pointer;padding:6px 14px;border:1px solid #bbb;border-radius:6px;background:#fff;font-size:14px}
button:hover{background:#f2f2f2}button:disabled{opacity:.5;cursor:default}
#sub{flex:1 1 320px;min-width:200px;padding:6px 8px;border:1px solid #ccc;border-radius:6px;font-family:monospace;font-size:13px}
#msg{font-size:14px;color:#555}
</style>
</head><body>
<h1>hosts-optimizer</h1>
<p>生成于 {{.GeneratedAt}} · 每 {{.ScheduleMinutes}} 分钟探测 · 生效 {{.ActiveCount}}/{{.DomainCount}} 个域名</p>
<div class="bar">
<input id="sub" type="text" readonly>
<button id="copy" type="button">复制订阅地址</button>
<button id="refresh" type="button">立即刷新</button>
<span id="msg"></span>
</div>
<p>在 AdGuard Home「过滤器 → DNS 封锁清单」添加上面的地址，更新间隔设为 1 小时（覆盖子域且让 AAAA 返回 NODATA）；也可用 <code>/hosts.txt</code>。域名清单在 <code>etc/domains.json</code>，改完点「立即刷新」即生效，无需重启；状态见 <code>/status.json</code>。</p>
{{if not .Ready}}<p>尚无有效 IP：请先添加域名并触发一轮探测。</p>{{end}}
<table><thead><tr><th>域名</th><th>生效 IP</th><th>延迟(ms)</th><th>候选/通过</th><th>说明</th></tr></thead><tbody>
{{range .Domains}}<tr><td>{{.Name}}</td><td>{{.IP}}</td><td>{{.LatencyMS}}</td><td>{{.Candidates}}/{{.Validated}}</td><td>{{.Reason}}</td></tr>{{end}}
</tbody></table>
<script>
(function () {
  var inp = document.getElementById('sub');
  var msg = document.getElementById('msg');
  inp.value = location.origin + '/agh.txt';
  document.getElementById('copy').onclick = function () {
    inp.select();
    try { document.execCommand('copy'); msg.textContent = '已复制'; }
    catch (e) { msg.textContent = '请手动复制上面的地址'; }
  };
  var btn = document.getElementById('refresh');
  btn.onclick = function () {
    btn.disabled = true;
    msg.textContent = '正在探测，请稍候…';
    fetch('/refresh', { method: 'POST' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.ok) {
          msg.textContent = '完成，即将刷新页面…';
          setTimeout(function () { location.reload(); }, 800);
        } else {
          msg.textContent = '失败：' + (j.error || '未知错误');
          btn.disabled = false;
        }
      })
      .catch(function (e) {
        msg.textContent = '请求失败：' + e;
        btn.disabled = false;
      });
  };
})();
</script>
</body></html>`))

func (a *App) index(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	if snap == nil {
		http.Error(w, "服务正在初始化，请稍后重试", http.StatusServiceUnavailable)
		return
	}
	data := struct {
		GeneratedAt     string
		ScheduleMinutes int
		ActiveCount     int
		DomainCount     int
		Ready           bool
		Domains         []output.StatusDomain
	}{
		GeneratedAt:     snap.Status.GeneratedAt.Format(time.RFC3339),
		ScheduleMinutes: snap.Status.ScheduleMinutes,
		ActiveCount:     snap.Status.ActiveCount,
		DomainCount:     snap.Status.DomainCount,
		Ready:           snap.Ready,
		Domains:         snap.Status.Domains,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, data); err != nil {
		log.Printf("渲染首页失败: %v", err)
	}
}
