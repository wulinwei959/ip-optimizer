// Package app 编排一轮探测、进程内定时、单端口 HTTP 服务与产物落盘。
package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	configPath                                string
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
		configPath:   filepath.Join(rt.ConfigDir, "domains.json"),
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
	case "/api/domains":
		a.handleDomainsConfig(w, r)
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

// handleDomainsConfig 在线读取 / 保存 domains.json。
//
//	GET      -> {"ok":true,"path":"...","raw":"..."}
//	PUT/POST -> 请求体为新的 domains.json 原文；校验通过后原子写回，失败返回 400 且不落盘
//
// 写请求强制要求 Content-Type: application/json：跨站表单无法携带该类型
// （会触发预检），而本服务不返回 CORS 头，可挡住简单的 CSRF 改写。
func (a *App) handleDomainsConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(a.configPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取配置失败: " + err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": a.configPath, "raw": string(data)})

	case http.MethodPut, http.MethodPost:
		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"ok": false, "error": "需要 Content-Type: application/json"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "读取请求体失败: " + err.Error()})
			return
		}
		if len(bytes.TrimSpace(body)) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求体为空"})
			return
		}
		if _, err := config.Parse(body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := util.AtomicWrite(a.configPath, body); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "写入配置失败: " + err.Error()})
			return
		}
		log.Printf("配置已更新: %s（%d 字节）", a.configPath, len(body))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(body), "path": a.configPath})

	default:
		w.Header().Set("Allow", "GET, PUT, POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET / PUT"})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>hosts-optimizer</title>
<style>
body{font-family:system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;line-height:1.6}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid #eee;padding:10px 12px;text-align:left;vertical-align:middle}
th{background:#fafafa;font-weight:600;color:#333;white-space:nowrap}
code{background:#f2f2f2;padding:2px 5px;border-radius:4px;font-size:13px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0}
button{cursor:pointer;padding:7px 16px;border:1px solid #ddd;border-radius:6px;background:#fff;font-size:14px;transition:all .15s}
button:hover{background:#f5f5f5;border-color:#ccc}
button:disabled{opacity:.5;cursor:not-allowed}
button.primary{background:#1976d2;color:#fff;border-color:#1976d2}
button.primary:hover{background:#1565c0;border-color:#1565c0}
button.danger{background:#fff;color:#d32f2f;border-color:#d32f2f}
button.danger:hover{background:#fef2f2;border-color:#d32f2f}
#sub{flex:1 1 320px;min-width:200px;padding:7px 10px;border:1px solid #ccc;border-radius:6px;font-family:monospace;font-size:13px}
#msg{font-size:14px;color:#555;min-width:180px}
#search{flex:1 1 240px;min-width:180px;padding:7px 10px;border:1px solid #ccc;border-radius:6px;font-size:13px}
#statusFilter{padding:7px 10px;border:1px solid #ccc;border-radius:6px;font-size:13px;background:#fff}
details{margin:18px 0;border-top:1px solid #eee;padding-top:12px}
summary{cursor:pointer;font-weight:600;padding:6px 0;color:#333}
.hint{color:#666;font-size:13px;margin:8px 0}
#cfg{width:100%;min-height:260px;box-sizing:border-box;font-family:ui-monospace,Consolas,monospace;font-size:13px;line-height:1.5;padding:10px;border:1px solid #ccc;border-radius:6px;resize:vertical}
#cfgMsg{font-size:14px;color:#555}
.status-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;vertical-align:middle}
.status-ok{background:#4caf50;box-shadow:0 0 6px #4caf50}
.status-fail{background:#f44336;box-shadow:0 0 6px #f44336}
.status-unknown{background:#9e9e9e}
.truncate{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;background:#e3f2fd;color:#1565c0;margin-left:6px}
.badge-ct{background:#fff3e0;color:#e65100}
.badge-wl{background:#e8f5e9;color:#2e7d32}
.badge-rl{background:#f3e5f5;color:#6a1b9a}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:100;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:#fff;border-radius:10px;padding:24px;width:90%;max-width:520px;max-height:80vh;overflow:auto;box-shadow:0 8px 30px rgba(0,0,.15)}
.modal h3{margin:0 0 16px;font-size:16px}
.modal .progress{margin:12px 0;height:6px;background:#eee;border-radius:3px;overflow:hidden}
.modal .progress-bar{height:100%;width:0%;background:#1976d2;transition:width .3s}
.modal .result-list{max-height:300px;overflow:auto;border:1px solid #eee;border-radius:6px;padding:8px;margin-top:12px}
.modal .result-item{display:flex;align-items:center;gap:10px;padding:6px 8px;border-radius:4px;font-size:13px}
.modal .result-item:hover{background:#f5f5f5}
.modal .result-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.modal .result-ok .result-dot{background:#4caf50}
.modal .result-fail .result-dot{background:#f44336}
.modal .result-info{flex:1;min-width:0}
.modal .result-domain{font-family:monospace;color:#333}
.modal .result-source{font-size:11px;padding:1px 6px;border-radius:8px}
.modal .result-ips{color:#666;font-size:12px;font-family:monospace}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px;padding-top:16px;border-top:1px solid #eee}
.table-row-hidden{display:none}
.pagination{display:flex;gap:6px;justify-content:center;margin-top:16px}
.pagination button{padding:5px 12px;font-size:13px}
.pagination button.active{background:#1976d2;color:#fff;border-color:#1976d2}
@media (max-width:768px){
  body{padding:0 10px}
  table{font-size:13px}
  th,td{padding:8px 6px}
  .truncate{max-width:160px}
}
</style>
</head><body>
<h1>hosts-optimizer</h1>
<p>生成于 {{.GeneratedAt}} · 每 {{.ScheduleMinutes}} 分钟轮询 · 有效 {{.ActiveCount}}/{{.DomainCount}} 个域名</p>

<div class="bar">
<input id="sub" type="text" readonly>
<button id="copy" type="button">复制订阅地址</button>
<button id="refresh" type="button">即时刷新</button>
<select id="statusFilter">
  <option value="all">全部</option>
  <option value="ok">正常</option>
  <option value="fail">失败</option>
</select>
<input id="search" type="text" placeholder="搜索域名/IP/说明...">
<span id="msg"></span>
</div>

<p>在 AdGuard Home、过滤器 -> DNS 重写清单、添加上述地址，更新间隔设为 1 小时（推荐子域名且开启 AAAA 返回 NODATA）；亦可用 <code>/hosts.txt</code>。详见 <code>/status.json</code></p>
{{if not .Ready}}<p style="color:#d32f2f">暂无有效 IP：请先添加域名并触发一轮轮询</p>{{end}}

<details>
<summary>编辑域名清单 (domains.json)</summary>
<p class="hint">保存前会校验：JSON 格式、域名合法、probe_dns 必须为字面 IP 等。配置会被固化且<strong>不会覆盖</strong>原文件；保存后点"生效"触发新一轮生成。</p>
<div class="bar">
<button id="cfgLoad" type="button">重新加载</button>
<button id="cfgSave" type="button">保存</button>
<button id="cfgSaveRun" type="button" class="primary">保存并生效</button>
<span id="cfgMsg"></span>
</div>
<textarea id="cfg" spellcheck="false"></textarea>
</details>

<table><thead>
<tr>
  <th style="width:20%">域名</th>
  <th style="width:16%">优选 IP</th>
  <th style="width:8%">延迟</th>
  <th style="width:12%">连接状态</th>
  <th style="width:10%">节点</th>
  <th style="width:34%">操作</th>
</tr>
</thead><tbody>
{{range $i, $d := .Domains}}
<tr data-name="{{$d.Name}}" data-ip="{{$d.IP}}" data-reason="{{$d.Reason}}" data-status="{{$d.Validated}}">
  <td class="truncate" title="{{$d.Name}}">{{$d.Name}}</td>
  <td class="truncate" title="{{$d.IP}}">{{$d.IP}}</td>
  <td>{{$d.LatencyMS}} ms</td>
  <td>
    <span class="status-dot {{if $d.Validated}}status-ok{{else}}status-fail{{end}}"></span>
    {{if $d.Validated}}正常{{else}}失败{{end}}
  </td>
  <td>{{$d.Candidates}}/{{$d.Validated}}</td>
  <td>
    <button type="button" class="expand-btn" data-domain="{{$d.Name}}">展开域名</button>
    <button type="button" class="refresh-btn" data-domain="{{$d.Name}}" title="单独刷新该域名">刷新</button>
    <span class="badge">{{$d.Reason}}</span>
  </td>
</tr>
{{end}}
</tbody></table>

<div class="pagination" id="pagination"></div>

<div class="modal-overlay" id="expandModal">
  <div class="modal">
    <h3>展开域名: <span id="modalDomain" style="font-family:monospace;color:#1976d2"></span></h3>
    <div class="progress"><div class="progress-bar" id="progressBar"></div></div>
    <p id="progressText" style="font-size:13px;color:#666;margin:8px 0">准备中...</p>
    <div class="result-list" id="resultList"></div>
    <div class="modal-actions">
      <button type="button" id="modalClose">关闭</button>
      <button type="button" id="modalAddAll" class="primary" disabled>全部添加到配置</button>
    </div>
  </div>
</div>

<script>
(function () {
  var inp = document.getElementById("sub");
  var msg = document.getElementById("msg");
  inp.value = location.origin + "/agh.txt";
  document.getElementById("copy").onclick = function () {
    inp.select();
    try { document.execCommand("copy"); msg.textContent = "已复制"; }
    catch (e) { msg.textContent = "请手动复制上方的地址"; }
  };
  var btn = document.getElementById("refresh");
  btn.onclick = function () {
    btn.disabled = true;
    msg.textContent = "正在轮询，请稍等";
    fetch("/refresh", { method: "POST" })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.ok) {
          msg.textContent = "完成，即将刷新页面";
          setTimeout(function () { location.reload(); }, 800);
        } else {
          msg.textContent = "失败: " + (j.error || "未知错误");
          btn.disabled = false;
        }
      })
      .catch(function (e) {
        msg.textContent = "请求失败: " + e;
        btn.disabled = false;
      });
  };

  var cfg = document.getElementById("cfg");
  var cfgMsg = document.getElementById("cfgMsg");
  function loadCfg() {
    cfgMsg.textContent = "加载中...";
    fetch("/api/domains")
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.ok) { cfg.value = j.raw; cfgMsg.textContent = ""; }
        else { cfgMsg.textContent = "加载失败: " + (j.error || "未知错误"); }
      })
      .catch(function (e) { cfgMsg.textContent = "加载失败: " + e; });
  }
  function saveCfg(thenRun) {
    cfgMsg.textContent = "保存中...";
    fetch("/api/domains", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: cfg.value
    }).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, body: j }; });
    }).then(function (x) {
      if (!x.body.ok) {
        cfgMsg.textContent = "保存失败: " + (x.body.error || ("HTTP " + x.status));
        return;
      }
      if (!thenRun) {
        cfgMsg.textContent = "已保存，点\"生效\"触发生成";
        return;
      }
      cfgMsg.textContent = "已保存，正在轮询...";
      fetch("/refresh", { method: "POST" })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (j.ok) {
            cfgMsg.textContent = "已保存并完成轮询，即将刷新页面";
            setTimeout(function () { location.reload(); }, 800);
          } else {
            cfgMsg.textContent = "轮询失败: " + (j.error || "未知错误");
          }
        });
    }).catch(function (e) { cfgMsg.textContent = "保存失败: " + e; });
  }
  document.getElementById("cfgLoad").onclick = loadCfg;
  document.getElementById("cfgSave").onclick = function () { saveCfg(false); };
  document.getElementById("cfgSaveRun").onclick = function () { saveCfg(true); };
  loadCfg();

  // 搜索筛选
  var searchInput = document.getElementById("search");
  var statusFilter = document.getElementById("statusFilter");
  var rows = document.querySelectorAll("tbody tr");
  var pagination = document.getElementById("pagination");
  var currentPage = 1;
  var pageSize = 20;

  function filterRows() {
    var kw = searchInput.value.trim().toLowerCase();
    var st = statusFilter.value;
    var visible = [];
    rows.forEach(function(tr) {
      var name = tr.dataset.name.toLowerCase();
      var ip = tr.dataset.ip.toLowerCase();
      var reason = tr.dataset.reason.toLowerCase();
      var validated = tr.dataset.status === "true";
      var match = !kw || name.indexOf(kw) >= 0 || ip.indexOf(kw) >= 0 || reason.indexOf(kw) >= 0;
      var statusMatch = st === "all" || (st === "ok" && validated) || (st === "fail" && !validated);
      if (match && statusMatch) visible.push(tr);
    });
    renderPagination(visible);
  }
  function renderPagination(visible) {
    var total = visible.length;
    var totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    var start = (currentPage - 1) * pageSize;
    var end = start + pageSize;
    rows.forEach(function(tr) { tr.classList.add("table-row-hidden"); });
    visible.slice(start, end).forEach(function(tr) { tr.classList.remove("table-row-hidden"); });
    pagination.innerHTML = "";
    if (totalPages <= 1) return;
    var prevBtn = document.createElement("button");
    prevBtn.textContent = "上一页";
    prevBtn.disabled = currentPage === 1;
    prevBtn.onclick = function() { currentPage--; filterRows(); };
    pagination.appendChild(prevBtn);
    var maxShow = 5;
    var startPage = Math.max(1, currentPage - Math.floor(maxShow/2));
    var endPage = Math.min(totalPages, startPage + maxShow - 1);
    if (endPage - startPage + 1 < maxShow) startPage = Math.max(1, endPage - maxShow + 1);
    for (var p = startPage; p <= endPage; p++) {
      var btn = document.createElement("button");
      btn.textContent = p;
      btn.className = p === currentPage ? "active" : "";
      btn.onclick = (function(page) { return function() { currentPage = page; filterRows(); }; })(p);
      pagination.appendChild(btn);
    }
    var nextBtn = document.createElement("button");
    nextBtn.textContent = "下一页";
    nextBtn.disabled = currentPage === totalPages;
    nextBtn.onclick = function() { currentPage++; filterRows(); };
    pagination.appendChild(nextBtn);
  }
  searchInput.addEventListener("input", function() { currentPage = 1; filterRows(); });
  statusFilter.addEventListener("change", function() { currentPage = 1; filterRows(); });
  filterRows();

  // 展开域名模态框
  var modal = document.getElementById("expandModal");
  var modalDomain = document.getElementById("modalDomain");
  var progressBar = document.getElementById("progressBar");
  var progressText = document.getElementById("progressText");
  var resultList = document.getElementById("resultList");
  var modalClose = document.getElementById("modalClose");
  var modalAddAll = document.getElementById("modalAddAll");
  var currentExpandDomain = "";
  var expandResults = [];

  function sourceLabel(src) {
    var map = {ct:"CT日志", wordlist:"字典", rules:"规则"};
    return map[src] || src;
  }
  function sourceClass(src) {
    var map = {ct:"badge-ct", wordlist:"badge-wl", rules:"badge-rl"};
    return map[src] || "";
  }

  document.querySelectorAll(".expand-btn").forEach(function(btn) {
    btn.onclick = function() {
      var domain = btn.dataset.domain;
      currentExpandDomain = domain;
      modalDomain.textContent = domain;
      progressBar.style.width = "0%";
      progressText.textContent = "正在查询子域名...";
      resultList.innerHTML = "";
      modalAddAll.disabled = true;
      modal.classList.add("show");
      doExpand(domain);
    };
  });

  function doExpand(domain) {
    fetch("/api/expand", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain, sources: ["ct","wordlist","rules"] })
    }).then(function(r) { return r.json(); })
      .then(function(j) {
        if (!j.ok) {
          progressText.textContent = "失败: " + (j.error || "未知错误");
          progressBar.style.width = "100%";
          progressBar.style.background = "#f44336";
          return;
        }
        expandResults = j.results || [];
        renderResults();
        progressBar.style.width = "100%";
        progressText.textContent = "完成: 共 " + expandResults.length + " 个子域名，" + expandResults.filter(function(r){return r.resolved}).length + " 个可解析";
        modalAddAll.disabled = expandResults.length === 0;
      })
      .catch(function(e) {
        progressText.textContent = "请求失败: " + e;
        progressBar.style.width = "100%";
        progressBar.style.background = "#f44336";
      });
  }

  function renderResults() {
    resultList.innerHTML = "";
    expandResults.forEach(function(r) {
      var item = document.createElement("div");
      item.className = "result-item " + (r.resolved ? "result-ok" : "result-fail");
      var ips = r.ips && r.ips.length ? r.ips.join(", ") : "\u2014";
      item.innerHTML =
        "<span class=\"result-dot\"></span>" +
        "<div class=\"result-info\">" +
        "  <div class=\"result-domain\">" + r.domain + "</div>" +
        "  <span class=\"result-source " + sourceClass(r.source) + "\">" + sourceLabel(r.source) + "</span>" +
        "</div>" +
        "<span class=\"result-ips\">" + ips + "</span>";
      resultList.appendChild(item);
    });
  }

  modalClose.onclick = function() { modal.classList.remove("show"); };
  modal.onclick = function(e) { if (e.target === modal) modal.classList.remove("show"); };

  modalAddAll.onclick = function() {
    var toAdd = expandResults.filter(function(r){return r.resolved}).map(function(r){return r.domain});
    if (toAdd.length === 0) return;
    var cfgText = cfg.value.trim();
    try {
      var cfgObj = JSON.parse(cfgText);
      var existing = new Set((cfgObj.domains || []).map(function(d){return d.name}));
      var added = 0;
      toAdd.forEach(function(d) {
        if (!existing.has(d)) {
          cfgObj.domains.push({name: d, expand: false});
          existing.add(d);
          added++;
        }
      });
      if (added > 0) {
        cfg.value = JSON.stringify(cfgObj, null, 2);
        cfgMsg.textContent = "已添加 " + added + " 个域名到配置，点\"保存并生效\"写入";
        modal.classList.remove("show");
      } else {
        alert("所有域名已存在于配置中");
      }
    } catch (e) {
      alert("配置解析失败: " + e);
    }
  };

  // 单独刷新域名
  document.querySelectorAll(".refresh-btn").forEach(function(btn) {
    btn.onclick = function() {
      var domain = btn.dataset.domain;
      btn.disabled = true;
      btn.textContent = "刷新中...";
      fetch("/refresh", { method: "POST" })
        .then(function(r) { return r.json(); })
        .then(function(j) {
          btn.disabled = false;
          btn.textContent = "刷新";
          if (j.ok) {
            msg.textContent = domain + " 刷新完成，即将刷新页面";
            setTimeout(function () { location.reload(); }, 800);
          } else {
            msg.textContent = "刷新失败: " + (j.error || "未知错误");
          }
        })
        .catch(function(e) {
          btn.disabled = false;
          btn.textContent = "刷新";
          msg.textContent = "请求失败: " + e;
        });
    };
  });
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