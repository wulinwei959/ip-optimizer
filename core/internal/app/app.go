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
	"hosts-optimizer/internal/expand"
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

	// 异步刷新任务
	refreshMu   sync.Mutex
	refreshTask *refreshTask
}

// 刷新任务状态取值。
const (
	refreshRunning = "running"
	refreshDone    = "done"
	refreshFailed  = "error"
)

// refreshTask 保存一次后台刷新任务的状态，供前端轮询进度。
type refreshTask struct {
	ID               string     `json:"id"`
	State            string     `json:"state"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	NextRoundMinutes int        `json:"next_round_minutes,omitempty"`
	Error            string     `json:"error,omitempty"`
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
	mux.HandleFunc("/api/refresh-status", a.handleRefreshStatus)
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

	targets := make([]config.Target, 0, len(rt.Config.Domains))
	seen := make(map[string]bool, len(rt.Config.Domains))
	for _, dom := range rt.Config.Domains {
		t := rt.Config.Resolve(dom)
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		targets = append(targets, t)
	}
	// 展开放在配置域名之后，确保用户在 domains.json 里的显式配置优先。
	base := append([]config.Target(nil), targets...)
	for _, t := range base {
		if !t.Expand {
			continue
		}
		for _, sub := range a.expandSubdomains(ctx, t, d) {
			if seen[sub.Name] {
				continue
			}
			seen[sub.Name] = true
			targets = append(targets, sub)
		}
	}

	entries := make([]output.Entry, 0, len(targets))
	for _, t := range targets {
		var ips []string
		if len(t.Candidates) > 0 {
			ips = t.Candidates
		} else {
			ips, err = dnsquery.CollectWithOptions(ctx, t.Name, d.ProbeDNS, dnsquery.Options{
				Timeout: timeout, AllowPrivate: t.AllowPrivate, Limit: d.MaxCandidates, RootCAs: a.rootCAs,
			})
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
	case "/api/expand":
		a.handleExpand(w, r)
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
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	taskID, reused := a.startRefresh()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "task_id": taskID, "reused": reused,
	})
}

// startRefresh 在后台启动一轮探测；已有任务在跑时直接复用，避免重复排队。
func (a *App) startRefresh() (string, bool) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if a.refreshTask != nil && a.refreshTask.State == refreshRunning {
		return a.refreshTask.ID, true
	}
	task := &refreshTask{
		ID:        fmt.Sprintf("r%d", time.Now().UnixNano()),
		State:     refreshRunning,
		StartedAt: time.Now(),
	}
	a.refreshTask = task
	go a.runRefresh(task)
	return task.ID, false
}

// runRefresh 执行后台轮次并回填任务状态。
// 使用独立 context：请求结束后探测不应被取消，各阶段仍有自身的超时控制。
func (a *App) runRefresh(task *refreshTask) {
	minutes, err := a.doRound(context.Background())
	finished := time.Now()
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	task.FinishedAt = &finished
	if err != nil {
		task.State = refreshFailed
		task.Error = err.Error()
		return
	}
	task.State = refreshDone
	task.NextRoundMinutes = minutes
}

// handleRefreshStatus 查询最近一次刷新任务的状态。
// 不传 task_id 时返回最近任务；尚无任务时返回 idle。
func (a *App) handleRefreshStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET"})
		return
	}
	id := r.URL.Query().Get("task_id")
	a.refreshMu.Lock()
	task := a.refreshTask
	var snap refreshTask
	if task != nil {
		snap = *task
	}
	a.refreshMu.Unlock()
	if task == nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "state": "idle"})
		return
	}
	if id != "" && id != snap.ID {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "未找到该刷新任务"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "id": snap.ID, "state": snap.State,
		"started_at": snap.StartedAt, "finished_at": snap.FinishedAt,
		"next_round_minutes": snap.NextRoundMinutes, "error": snap.Error,
	})
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

// expandSubdomains 对开启 expand 的主域名做一次发现，把可解析的子域名转成待探测目标。
// 展开失败只记录日志并跳过，不影响本轮其余域名。
func (a *App) expandSubdomains(ctx context.Context, t config.Target, d config.Defaults) []config.Target {
	sources, err := parseExpandSources(t.ExpandSources)
	if err != nil {
		log.Printf("[%s] 展开来源配置非法，已跳过: %v", t.Name, err)
		return nil
	}
	timeout := time.Duration(t.ExpandTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	expander := expand.New(expand.Options{
		Sources:       sources,
		Concurrency:   t.ExpandConcurrency,
		Timeout:       timeout,
		MaxSubdomains: t.ExpandMaxSubdomains,
		ProbeDNS:      d.ProbeDNS,
	})
	expandCtx, cancel := context.WithTimeout(ctx, timeout+timeout/2)
	defer cancel()
	results, err := expander.Expand(expandCtx, t.Name)
	if err != nil {
		log.Printf("[%s] 域名展开失败: %v", t.Name, err)
		return nil
	}
	subs := make([]config.Target, 0, len(results))
	for _, r := range results {
		if !r.Resolved || len(r.IPs) == 0 {
			continue
		}
		sub := t
		sub.Name = r.Domain
		sub.SNI = r.Domain
		sub.Candidates = append([]string(nil), r.IPs...)
		sub.Expand = false
		subs = append(subs, sub)
	}
	if len(subs) > 0 {
		log.Printf("[%s] 域名展开：%d 个子域名可解析", t.Name, len(subs))
	}
	return subs
}

// handleExpand 按需展开主域名，返回发现的子域名及其解析结果。
// 只做发现与 DNS 校验，不修改配置、不触发探测轮次。
func (a *App) handleExpand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"ok": false, "error": "需要 Content-Type: application/json"})
		return
	}
	var req struct {
		Domain  string   `json:"domain"`
		Sources []string `json:"sources"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析请求失败: " + err.Error()})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "domain 不能为空"})
		return
	}
	rt, err := config.Load()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "加载配置失败: " + err.Error()})
		return
	}
	d := rt.Config.Defaults
	sources, err := parseExpandSources(req.Sources)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(sources) == 0 {
		sources, _ = parseExpandSources(d.ExpandSources)
	}
	timeout := time.Duration(d.ExpandTimeoutSeconds) * time.Second
	expander := expand.New(expand.Options{
		Sources:       sources,
		Concurrency:   d.ExpandConcurrency,
		Timeout:       timeout,
		MaxSubdomains: d.ExpandMaxSubdomains,
		ProbeDNS:      d.ProbeDNS,
	})
	ctx, cancel := context.WithTimeout(r.Context(), timeout+timeout/2)
	defer cancel()
	results, err := expander.Expand(ctx, domain)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domain": domain, "results": results})
}

// parseExpandSources 校验并去重展开来源，空列表表示使用全局默认。
func parseExpandSources(values []string) ([]expand.Source, error) {
	out := make([]expand.Source, 0, len(values))
	seen := make(map[expand.Source]bool, len(values))
	for _, v := range values {
		s := expand.Source(strings.ToLower(strings.TrimSpace(v)))
		switch s {
		case expand.SourceCT, expand.SourceWordlist, expand.SourceRules:
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		default:
			return nil, fmt.Errorf("非法展开来源 %q，合法值: ct/wordlist/rules", v)
		}
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>hosts-optimizer</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--line:#e5e8ee;--text:#1f2937;--muted:#6b7280;--accent:#2563eb;--accent-dark:#1d4ed8;--danger:#dc2626;--ok:#16a34a;--radius:12px}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",sans-serif;background:var(--bg);color:var(--text);max-width:1180px;margin:0 auto;padding:30px 20px 56px;line-height:1.65}
h1{font-size:30px;letter-spacing:-.02em;margin:0 0 8px}
.sub{color:var(--muted);font-size:14px;margin:0 0 2px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;margin:16px 0;box-shadow:0 1px 2px rgba(16,24,40,.04)}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--line);padding:12px;text-align:left;vertical-align:middle}
th{background:#f8fafc;font-weight:600;color:#374151;white-space:nowrap;font-size:13px}
tbody tr:hover{background:#f9fafb}
tbody tr:last-child td{border-bottom:none}
code{background:#eef2f7;padding:2px 6px;border-radius:5px;font-size:13px}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
button{cursor:pointer;padding:8px 16px;border:1px solid #d7dce5;border-radius:8px;background:#fff;color:#1f2937;font-size:14px;font-family:inherit;transition:background .15s,border-color .15s,box-shadow .15s}
button:hover{background:#f3f4f6;border-color:#c3c9d4}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid rgba(37,99,235,.35);outline-offset:1px}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.primary:hover{background:var(--accent-dark);border-color:var(--accent-dark)}
button.danger{background:#fff;color:var(--danger);border-color:#f0b4b4}
button.danger:hover{background:#fef2f2;border-color:var(--danger)}
input[type=text],input[type=number],select{padding:8px 11px;border:1px solid #d7dce5;border-radius:8px;font-size:13px;font-family:inherit;background:#fff;color:var(--text)}
#sub{flex:1 1 320px;min-width:200px;font-family:ui-monospace,Consolas,monospace}
#msg{font-size:14px;color:var(--muted);min-width:180px}
#search{flex:1 1 240px;min-width:180px}
#statusFilter{background:#fff}
details{margin:16px 0 0}
summary{cursor:pointer;font-weight:600;padding:6px 0;color:#111827;font-size:15px}
summary::marker{color:var(--accent)}
.hint{color:var(--muted);font-size:13px;margin:8px 0}
#cfg{width:100%;min-height:260px;font-family:ui-monospace,Consolas,monospace;font-size:13px;line-height:1.55;padding:12px;border:1px solid #d7dce5;border-radius:8px;resize:vertical;background:#fbfcfe}
#cfgMsg{font-size:14px;color:var(--muted)}
.status-dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:8px;vertical-align:middle}
.status-ok{background:var(--ok);box-shadow:0 0 6px rgba(22,163,74,.5)}
.status-fail{background:#ef4444;box-shadow:0 0 6px rgba(239,68,68,.5)}
.status-unknown{background:#9ca3af}
.truncate{max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;vertical-align:middle}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;background:#eff6ff;color:#1d4ed8;margin-left:6px;white-space:nowrap}
.badge-ct{background:#fff7ed;color:#c2410c}
.badge-wl{background:#ecfdf5;color:#047857}
.badge-rl{background:#f5f3ff;color:#6d28d9}
.discover{border:1px dashed #cfd6e2;background:#fafbfe;border-radius:10px;padding:12px;margin:10px 0 14px}
.discover-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
#discoverInput{flex:1 1 280px;min-width:200px}
.dropdown{position:relative;flex:0 0 auto}
#discoverToggle{min-width:136px}
#discoverToggle .pill{display:inline-block;min-width:20px;padding:0 6px;margin-left:4px;border-radius:999px;background:var(--accent);color:#fff;font-size:12px;line-height:18px;text-align:center}
.dropdown-panel{display:none;position:absolute;top:calc(100% + 6px);right:0;left:auto;z-index:40;width:min(460px,calc(100vw - 32px));max-height:70vh;background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 32px rgba(16,24,40,.16);overflow:hidden}
.dropdown.open .dropdown-panel{display:block}
.dropdown-head{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 12px;border-bottom:1px solid var(--line);background:#f8fafc;font-size:13px}
.dropdown-head label{display:flex;align-items:center;gap:7px;cursor:pointer;font-weight:600}
.dropdown-head .muted{color:var(--muted)}
.dropdown-list{max-height:320px;overflow:auto}
.dropdown-item{display:flex;align-items:center;gap:9px;padding:8px 12px;border-bottom:1px solid #f1f3f7;font-size:13px;cursor:pointer}
.dropdown-item:last-child{border-bottom:none}
.dropdown-item:hover{background:#f5f8ff}
.dropdown-item.disabled{opacity:.55;cursor:not-allowed;background:#fafafa}
.dropdown-item input{margin:0;accent-color:var(--accent);flex:0 0 auto}
.dropdown-item .domain{font-family:ui-monospace,Consolas,monospace;color:#111827;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.dropdown-item .meta{color:var(--muted);font-size:12px;white-space:nowrap}
.dropdown-empty{padding:18px 12px;text-align:center;color:var(--muted);font-size:13px}
.cfg-tabs{display:inline-flex;gap:4px;padding:3px;background:#eef2f7;border-radius:9px;margin:10px 0 14px}
.cfg-tabs button{border:none;background:transparent;padding:6px 14px;font-size:13px;border-radius:7px}
.cfg-tabs button.active{background:#fff;color:var(--accent);box-shadow:0 1px 3px rgba(16,24,40,.12)}
.cfg-form{display:none}
.cfg-form.active{display:block}
.cfg-json-wrap{display:none}
.cfg-json-wrap.active{display:block}
.cfg-section{border:1px solid var(--line);border-radius:10px;padding:12px 14px 14px;margin:0 0 12px}
.cfg-section legend{padding:0 6px;font-size:13px;font-weight:600;color:#374151}
.field-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.field-grid label{display:flex;flex-direction:column;gap:5px;font-size:13px;color:#4b5563}
.field-grid label.wide{grid-column:1/-1}
.field-grid input[type=text],.field-grid input[type=number]{width:100%}
.checks{display:flex;flex-wrap:wrap;gap:14px;padding:6px 0}
.checks label{flex-direction:row;align-items:center;gap:6px;font-size:13px;color:#374151;cursor:pointer}
.checks input{accent-color:var(--accent)}
.domain-editor{display:flex;flex-direction:column;gap:8px}
.domain-item{border:1px solid var(--line);border-radius:9px;background:#fff;overflow:hidden}
.domain-main{display:flex;flex-wrap:wrap;align-items:center;gap:10px;padding:9px 11px}
.domain-main .d-name{flex:1 1 240px;min-width:160px;font-family:ui-monospace,Consolas,monospace}
.domain-main label{display:flex;align-items:center;gap:6px;font-size:13px;color:#4b5563;white-space:nowrap;cursor:pointer}
.domain-main input[type=checkbox]{width:15px;height:15px;accent-color:var(--accent);margin:0}
.domain-adv{display:none;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;padding:10px 11px;border-top:1px dashed var(--line);background:#fafbfe}
.domain-item.open .domain-adv{display:grid}
.domain-adv label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}
.domain-adv input{width:100%}
.domain-empty{color:var(--muted);font-size:13px;padding:6px 2px;margin:0}
.table-tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;margin-bottom:10px}
.table-tools .left{display:flex;gap:10px;align-items:center}
#selCount{font-size:13px;color:var(--muted)}
.select-cell{width:42px}
.select-cell input{width:15px;height:15px;accent-color:var(--accent);cursor:pointer;margin:0}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(17,24,39,.45);z-index:100;align-items:center;justify-content:center;padding:16px}
.modal-overlay.show{display:flex}
.modal{background:#fff;border-radius:12px;padding:24px;width:90%;max-width:560px;max-height:82vh;overflow:auto;box-shadow:0 20px 50px rgba(16,24,40,.25)}
.modal h3{margin:0 0 16px;font-size:16px}
.modal .progress{margin:12px 0;height:6px;background:#eef1f6;border-radius:3px;overflow:hidden}
.modal .progress-bar{height:100%;width:0%;background:var(--accent);transition:width .3s}
.modal .result-list{max-height:320px;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:8px;margin-top:12px}
.modal .result-item{display:flex;align-items:center;gap:10px;padding:6px 8px;border-radius:6px;font-size:13px}
.modal .result-item:hover{background:#f6f8fb}
.modal .result-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.modal .result-ok .result-dot{background:var(--ok)}
.modal .result-fail .result-dot{background:#ef4444}
.modal .result-info{flex:1;min-width:0}
.modal .result-domain{font-family:ui-monospace,Consolas,monospace;color:#111827}
.modal .result-source{font-size:11px;padding:1px 6px;border-radius:8px}
.modal .result-ips{color:var(--muted);font-size:12px;font-family:ui-monospace,Consolas,monospace}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:16px;padding-top:16px;border-top:1px solid var(--line)}
.table-row-hidden{display:none}
.group-row td{background:#f7f9fc;padding:0}
.group-row.open td{background:#eff4fb}
.group-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:6px 12px}
.group-toggle{display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid transparent;border-radius:8px;background:transparent;font-size:14px;font-weight:600;color:#111827}
.group-toggle:hover{background:#e8eef8;border-color:#d5deec}
.group-toggle .caret{width:14px;color:var(--accent);font-size:11px;text-align:center}
.group-name{font-family:ui-monospace,Consolas,monospace}
.group-count{font-weight:400;color:var(--muted);font-size:13px}
.group-ok{font-weight:400;color:var(--ok);font-size:13px}
.group-ok.has-bad{color:#b45309}
.group-select{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);cursor:pointer;white-space:nowrap}
.group-select input{width:15px;height:15px;accent-color:var(--accent);margin:0}
tr.domain-row td{background:#fff}
tr.domain-row td:nth-child(2){padding-left:32px}
@media (max-width:768px){
  body{padding:18px 12px 40px}
  h1{font-size:24px}
  table{font-size:13px}
  th,td{padding:9px 7px}
  .truncate{max-width:150px}
  .card{padding:14px}
  #discoverInput{flex:1 1 100%}
}
</style>
</head><body>
<h1>hosts-optimizer</h1>
<p class="sub">生成于 {{.GeneratedAt}} · 每 {{.ScheduleMinutes}} 分钟轮询 · 有效 {{.ActiveCount}}/{{.DomainCount}} 个域名</p>

<div class="card">
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

<p class="hint">在 AdGuard Home、过滤器 -> DNS 重写清单、添加上述地址，更新间隔设为 1 小时（推荐子域名且开启 AAAA 返回 NODATA）；亦可用 <code>/hosts.txt</code>。详见 <code>/status.json</code></p>
{{if not .Ready}}<p style="color:#d32f2f">暂无有效 IP：请先添加域名并触发一轮轮询</p>{{end}}
</div>

<div class="card">
<details>
<summary>编辑域名清单 (domains.json)</summary>
<div class="discover">
  <div class="discover-row">
    <input id="discoverInput" type="text" placeholder="输入主域名，如 github.com" spellcheck="false" autocomplete="off">
    <button id="discoverBtn" type="button" class="primary">获取域名列表</button>
    <div class="dropdown" id="discoverDropdown">
      <button id="discoverToggle" type="button" disabled>选择域名<span class="pill" id="discoverCount">0</span></button>
      <div class="dropdown-panel">
        <div class="dropdown-head">
          <label><input type="checkbox" id="discoverAll"> 全选</label>
          <span class="muted" id="discoverSummary">尚未获取</span>
        </div>
        <div class="dropdown-list" id="discoverList"><div class="dropdown-empty">输入主域名后点「获取域名列表」</div></div>
      </div>
    </div>
    <button id="discoverAdd" type="button" disabled>添加</button>
  </div>
  <p class="hint" id="discoverMsg">输入主域名后会从 CT 日志、字典与规则中发现相关子域名；勾选后点「添加」写入下方配置，再点「保存并生效」。</p>
</div>
<div class="cfg-tabs">
  <button id="tabForm" type="button" class="active">图形化</button>
  <button id="tabJSON" type="button">JSON 源码</button>
</div>

<div id="cfgForm" class="cfg-form active">
  <fieldset class="cfg-section">
    <legend>定时与探测</legend>
    <div class="field-grid">
      <label>轮询周期（分钟）<input id="fSchedule" type="number" min="1"></label>
      <label>探测端口<input id="fPort" type="number" min="1" max="65535"></label>
      <label>并发数<input id="fConcurrency" type="number" min="1"></label>
      <label>最大候选 IP 数<input id="fMaxCandidates" type="number" min="1"></label>
      <label>TCP 探测轮数<input id="fTCPRounds" type="number" min="1"></label>
      <label>单次超时（秒）<input id="fTimeout" type="number" min="1"></label>
    </div>
  </fieldset>
  <fieldset class="cfg-section">
    <legend>DNS 与切换策略</legend>
    <div class="field-grid">
      <label class="wide">探测 DNS（逗号分隔）<input id="fProbeDNS" type="text" placeholder="223.5.5.5, tls://dns.alidns.com, https://dns.cloudflare.com/dns-query"></label>
      <label>滞回百分比（%）<input id="fHystPct" type="number" min="0"></label>
      <label>滞回轮数<input id="fHystRounds" type="number" min="1"></label>
    </div>
    <p class="hint" style="margin:8px 0 0">支持 UDP（字面 IP）、DoT（tls://主机[:853]）、DoH（https://主机/路径），可混用；DoQ 暂不支持。</p>
  </fieldset>
  <fieldset class="cfg-section">
    <legend>子域名展开</legend>
    <div class="field-grid">
      <label class="wide">默认展开来源
        <span class="checks">
          <label><input type="checkbox" id="fSrcCT" value="ct"> CT 日志</label>
          <label><input type="checkbox" id="fSrcWL" value="wordlist"> 字典</label>
          <label><input type="checkbox" id="fSrcRules" value="rules"> 规则</label>
        </span>
      </label>
      <label>展开并发<input id="fExpandConcurrency" type="number" min="1"></label>
      <label>展开超时（秒）<input id="fExpandTimeout" type="number" min="1"></label>
      <label>最多子域名<input id="fExpandMax" type="number" min="1"></label>
    </div>
  </fieldset>
  <fieldset class="cfg-section">
    <legend>域名列表</legend>
    <div id="domainEditor" class="domain-editor"></div>
    <div class="bar" style="margin-top:10px">
      <input id="newDomainName" type="text" placeholder="新增域名，如 example.com" spellcheck="false">
      <button id="addDomainBtn" type="button">添加域名</button>
    </div>
  </fieldset>
</div>

<div id="cfgJSONWrap" class="cfg-json-wrap">
  <textarea id="cfg" spellcheck="false"></textarea>
</div>

<p class="hint">保存前会校验：JSON 格式、域名合法、probe_dns 必须为字面 IP 等。配置会被固化且<strong>不会覆盖</strong>原文件；保存后点「保存并生效」触发新一轮生成。</p>
<div class="bar">
<button id="cfgLoad" type="button">重新加载</button>
<button id="cfgSave" type="button">保存</button>
<button id="cfgSaveRun" type="button" class="primary">保存并生效</button>
<span id="cfgMsg"></span>
</div>
</details>
</div>

<div class="card">
<div class="table-tools">
  <div class="left">
    <span id="selCount">已选 0 个域名</span>
    <button id="batchDelete" type="button" class="danger" disabled>删除选中</button>
    <button id="expandAll" type="button">全部展开</button>
    <button id="collapseAll" type="button">全部收起</button>
  </div>
  <span class="hint" style="margin:0">按主域名分组；点分组标题展开该分类，勾选后可批量删除</span>
</div>
<table><thead>
<tr>
  <th class="select-cell"><input type="checkbox" id="selectAll" title="全选筛选结果"></th>
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
  <td class="select-cell"><input type="checkbox" class="row-check" value="{{$d.Name}}"></td>
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

</div>

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
  // 刷新改为后台任务：POST 拿到 task_id 后轮询状态，避免长请求卡住页面。
  function startRefresh(statusEl, done) {
    statusEl.textContent = "正在轮询，请稍等";
    fetch("/refresh", { method: "POST" })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (x) {
        if (!x.body.ok || !x.body.task_id) {
          throw new Error(x.body.error || ("HTTP " + x.status));
        }
        var taskId = x.body.task_id;
        var timer = setInterval(function () {
          fetch("/api/refresh-status?task_id=" + encodeURIComponent(taskId))
            .then(function (r) { return r.json(); })
            .then(function (s) {
              if (s.state === "running") {
                statusEl.textContent = "正在轮询，请稍等";
                return;
              }
              clearInterval(timer);
              if (s.state === "done") {
                statusEl.textContent = "完成，即将刷新页面";
                if (done) done(true);
                setTimeout(function () { location.reload(); }, 600);
                return;
              }
              statusEl.textContent = "失败: " + (s.error || "未知错误");
              if (done) done(false);
            })
            .catch(function (e) {
              clearInterval(timer);
              statusEl.textContent = "状态查询失败: " + e;
              if (done) done(false);
            });
        }, 1000);
      })
      .catch(function (e) {
        statusEl.textContent = "请求失败: " + e.message;
        if (done) done(false);
      });
  }
  btn.onclick = function () {
    btn.disabled = true;
    startRefresh(msg, function () { btn.disabled = false; });
  };

  var cfg = document.getElementById("cfg");
  var cfgMsg = document.getElementById("cfgMsg");
  var cfgTab = "form";
  var cfgFormEl = document.getElementById("cfgForm");
  var cfgJSONWrap = document.getElementById("cfgJSONWrap");
  var tabFormBtn = document.getElementById("tabForm");
  var tabJSONBtn = document.getElementById("tabJSON");
  var domainEditor = document.getElementById("domainEditor");

  function splitList(v) {
    return String(v || "").split(/[,，\s]+/).map(function (s) { return s.trim(); })
      .filter(function (s) { return s.length > 0; });
  }
  function setNum(obj, key, el, fallback) {
    var raw = el.value.trim();
    var n = raw === "" ? NaN : parseInt(raw, 10);
    obj[key] = isNaN(n) ? fallback : n;
  }
  function numTo(el, v, fallback) {
    el.value = String((v === undefined || v === null || v === "") ? fallback : v);
  }
  function advField(labelText, cls, value, type) {
    var label = document.createElement("label");
    label.appendChild(document.createTextNode(labelText));
    var input = document.createElement("input");
    input.type = type || "text";
    input.className = cls;
    input.value = value;
    label.appendChild(input);
    return label;
  }
  function buildDomainRow(d) {
    var item = document.createElement("div");
    item.className = "domain-item";
    item._src = d;

    var main = document.createElement("div");
    main.className = "domain-main";
    var name = document.createElement("input");
    name.type = "text";
    name.className = "d-name";
    name.value = d.name || "";
    name.placeholder = "example.com";
    name.spellcheck = false;

    var expandLabel = document.createElement("label");
    var expand = document.createElement("input");
    expand.type = "checkbox";
    expand.className = "d-expand";
    expand.checked = !!d.expand;
    expandLabel.appendChild(expand);
    expandLabel.appendChild(document.createTextNode(" 展开子域名"));

    var advBtn = document.createElement("button");
    advBtn.type = "button";
    advBtn.textContent = "高级";
    advBtn.onclick = function () { item.classList.toggle("open"); };

    var delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "danger";
    delBtn.textContent = "删除";
    delBtn.onclick = function () { item.remove(); };

    main.appendChild(name);
    main.appendChild(expandLabel);
    main.appendChild(advBtn);
    main.appendChild(delBtn);

    var adv = document.createElement("div");
    adv.className = "domain-adv";
    adv.appendChild(advField("SNI（留空同域名）", "d-sni", d.sni || ""));
    adv.appendChild(advField("端口（留空用默认）", "d-port", d.port ? String(d.port) : "", "number"));
    adv.appendChild(advField("候选 IP（逗号分隔）", "d-cands", (d.candidates || []).join(", ")));
    adv.appendChild(advField("展开来源（ct/wordlist/rules）", "d-sources", (d.expand_sources || []).join(", ")));

    item.appendChild(main);
    item.appendChild(adv);
    return item;
  }
  function fillForm(raw) {
    var obj;
    try {
      obj = JSON.parse(raw || "{}");
    } catch (e) {
      cfgMsg.textContent = "JSON 解析失败，请先在 JSON 模式修正: " + e.message;
      return false;
    }
    var d = obj.defaults || {};
    numTo(document.getElementById("fSchedule"), d.schedule_minutes, 60);
    numTo(document.getElementById("fPort"), d.probe_port, 443);
    numTo(document.getElementById("fConcurrency"), d.concurrency, 20);
    numTo(document.getElementById("fMaxCandidates"), d.max_candidates, 64);
    numTo(document.getElementById("fTCPRounds"), d.tcp_rounds, 3);
    numTo(document.getElementById("fTimeout"), d.timeout_seconds, 3);
    numTo(document.getElementById("fHystPct"), d.hysteresis_percent, 0);
    numTo(document.getElementById("fHystRounds"), d.hysteresis_rounds, 2);
    numTo(document.getElementById("fExpandConcurrency"), d.expand_concurrency, 10);
    numTo(document.getElementById("fExpandTimeout"), d.expand_timeout_seconds, 10);
    numTo(document.getElementById("fExpandMax"), d.expand_max_subdomains, 50);
    var dnsList = (d.probe_dns && d.probe_dns.length) ? d.probe_dns : ["223.5.5.5", "119.29.29.29"];
    document.getElementById("fProbeDNS").value = dnsList.join(", ");
    var srcs = (d.expand_sources && d.expand_sources.length) ? d.expand_sources : ["wordlist", "rules"];
    document.getElementById("fSrcCT").checked = srcs.indexOf("ct") >= 0;
    document.getElementById("fSrcWL").checked = srcs.indexOf("wordlist") >= 0;
    document.getElementById("fSrcRules").checked = srcs.indexOf("rules") >= 0;

    domainEditor.innerHTML = "";
    var list = Array.isArray(obj.domains) ? obj.domains : [];
    list.forEach(function (dom) {
      if (!dom || !dom.name) return;
      var copy = {};
      Object.keys(dom).forEach(function (k) { copy[k] = dom[k]; });
      domainEditor.appendChild(buildDomainRow(copy));
    });
    if (domainEditor.children.length === 0) {
      var empty = document.createElement("p");
      empty.className = "domain-empty";
      empty.textContent = "还没有域名，可在下方新增，或用上方「获取域名列表」批量添加";
      domainEditor.appendChild(empty);
    }
    return true;
  }
  function formToConfig() {
    var obj;
    try {
      obj = JSON.parse(cfg.value || "{}");
    } catch (e) {
      throw new Error("JSON 源码有误，请先切到 JSON 模式修正: " + e.message);
    }
    if (!obj.defaults) obj.defaults = {};
    var d = obj.defaults;
    setNum(d, "schedule_minutes", document.getElementById("fSchedule"), 60);
    setNum(d, "probe_port", document.getElementById("fPort"), 443);
    setNum(d, "concurrency", document.getElementById("fConcurrency"), 20);
    setNum(d, "max_candidates", document.getElementById("fMaxCandidates"), 64);
    setNum(d, "tcp_rounds", document.getElementById("fTCPRounds"), 3);
    setNum(d, "timeout_seconds", document.getElementById("fTimeout"), 3);
    setNum(d, "hysteresis_percent", document.getElementById("fHystPct"), 0);
    setNum(d, "hysteresis_rounds", document.getElementById("fHystRounds"), 2);
    setNum(d, "expand_concurrency", document.getElementById("fExpandConcurrency"), 10);
    setNum(d, "expand_timeout_seconds", document.getElementById("fExpandTimeout"), 10);
    setNum(d, "expand_max_subdomains", document.getElementById("fExpandMax"), 50);
    var dns = splitList(document.getElementById("fProbeDNS").value);
    d.probe_dns = dns.length ? dns : ["223.5.5.5", "119.29.29.29"];
    var srcs = [];
    if (document.getElementById("fSrcCT").checked) srcs.push("ct");
    if (document.getElementById("fSrcWL").checked) srcs.push("wordlist");
    if (document.getElementById("fSrcRules").checked) srcs.push("rules");
    d.expand_sources = srcs.length ? srcs : ["wordlist", "rules"];

    var domains = [];
    Array.prototype.forEach.call(domainEditor.querySelectorAll(".domain-item"), function (item) {
      var src = item._src || {};
      var base = {};
      Object.keys(src).forEach(function (k) { base[k] = src[k]; });
      var name = item.querySelector(".d-name").value.trim().toLowerCase();
      if (!name) return;
      base.name = name;
      base.expand = item.querySelector(".d-expand").checked;
      var sni = item.querySelector(".d-sni").value.trim();
      if (sni) base.sni = sni; else delete base.sni;
      var port = item.querySelector(".d-port").value.trim();
      if (port) {
        var p = parseInt(port, 10);
        if (!isNaN(p)) base.port = p;
      } else {
        delete base.port;
      }
      var cands = splitList(item.querySelector(".d-cands").value);
      if (cands.length) base.candidates = cands; else delete base.candidates;
      var es = splitList(item.querySelector(".d-sources").value);
      if (es.length) base.expand_sources = es; else delete base.expand_sources;
      domains.push(base);
    });
    obj.domains = domains;
    cfg.value = JSON.stringify(obj, null, 2);
  }
  function syncFormIfNeeded() {
    if (cfgTab === "form") formToConfig();
  }
  function setTab(tab) {
    if (tab === cfgTab) return;
    if (tab === "json") {
      try {
        formToConfig();
      } catch (e) {
        cfgMsg.textContent = e.message;
        return;
      }
    } else if (!fillForm(cfg.value)) {
      return;
    }
    cfgTab = tab;
    var isForm = tab === "form";
    cfgFormEl.classList.toggle("active", isForm);
    cfgJSONWrap.classList.toggle("active", !isForm);
    tabFormBtn.classList.toggle("active", isForm);
    tabJSONBtn.classList.toggle("active", !isForm);
    cfgMsg.textContent = "";
  }
  tabFormBtn.onclick = function () { setTab("form"); };
  tabJSONBtn.onclick = function () { setTab("json"); };

  document.getElementById("addDomainBtn").onclick = function () {
    var input = document.getElementById("newDomainName");
    var name = input.value.trim().toLowerCase();
    if (!name) { input.focus(); return; }
    var empty = domainEditor.querySelector(".domain-empty");
    if (empty) empty.remove();
    var item = buildDomainRow({ name: name, expand: false });
    domainEditor.appendChild(item);
    input.value = "";
    item.scrollIntoView({ block: "nearest" });
  };
  document.getElementById("newDomainName").addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      document.getElementById("addDomainBtn").click();
    }
  });

  function loadCfg() {
    cfgMsg.textContent = "加载中...";
    fetch("/api/domains")
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.ok) {
          cfg.value = j.raw;
          cfgMsg.textContent = "";
          if (cfgTab === "form") fillForm(j.raw);
        } else {
          cfgMsg.textContent = "加载失败: " + (j.error || "未知错误");
        }
      })
      .catch(function (e) { cfgMsg.textContent = "加载失败: " + e; });
  }
  function saveCfg(thenRun) {
    if (cfgTab === "form") {
      try {
        formToConfig();
      } catch (e) {
        cfgMsg.textContent = e.message;
        return;
      }
    }
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
      startRefresh(cfgMsg);
    }).catch(function (e) { cfgMsg.textContent = "保存失败: " + e; });
  }
  document.getElementById("cfgLoad").onclick = loadCfg;
  document.getElementById("cfgSave").onclick = function () { saveCfg(false); };
  document.getElementById("cfgSaveRun").onclick = function () { saveCfg(true); };
  loadCfg();

  // 域名发现：输入主域名 -> 获取相关子域名 -> 勾选 -> 添加到配置
  var discoverInput = document.getElementById("discoverInput");
  var discoverBtn = document.getElementById("discoverBtn");
  var discoverDropdown = document.getElementById("discoverDropdown");
  var discoverToggle = document.getElementById("discoverToggle");
  var discoverListEl = document.getElementById("discoverList");
  var discoverAll = document.getElementById("discoverAll");
  var discoverCount = document.getElementById("discoverCount");
  var discoverAdd = document.getElementById("discoverAdd");
  var discoverMsg = document.getElementById("discoverMsg");
  var discoverSummary = document.getElementById("discoverSummary");
  var discovered = [];

  function openDropdown(open) {
    discoverDropdown.classList.toggle("open", open);
  }
  discoverToggle.onclick = function () {
    openDropdown(!discoverDropdown.classList.contains("open"));
  };
  document.addEventListener("click", function (e) {
    if (!discoverDropdown.contains(e.target)) openDropdown(false);
  });

  function checkedDomains() {
    return discovered.filter(function (r) { return r.checked && r.resolved; })
      .map(function (r) { return r.domain; });
  }
  function refreshDiscoverState() {
    var n = checkedDomains().length;
    discoverCount.textContent = String(n);
    discoverAdd.disabled = n === 0;
    var resolvedList = discovered.filter(function (r) { return r.resolved; });
    discoverSummary.textContent = discovered.length
      ? "共 " + discovered.length + " 个，" + resolvedList.length + " 个可解析"
      : "尚未获取";
    discoverAll.disabled = resolvedList.length === 0;
    discoverAll.checked = resolvedList.length > 0 && resolvedList.every(function (r) { return r.checked; });
  }
  function renderDiscovered() {
    discoverListEl.innerHTML = "";
    if (discovered.length === 0) {
      var empty = document.createElement("div");
      empty.className = "dropdown-empty";
      empty.textContent = "没有发现可用的相关域名";
      discoverListEl.appendChild(empty);
      refreshDiscoverState();
      return;
    }
    discovered.forEach(function (r) {
      var item = document.createElement("label");
      item.className = "dropdown-item" + (r.resolved ? "" : " disabled");
      var box = document.createElement("input");
      box.type = "checkbox";
      box.checked = r.checked;
      box.disabled = !r.resolved;
      box.onchange = function () { r.checked = box.checked; refreshDiscoverState(); };
      var name = document.createElement("span");
      name.className = "domain";
      name.textContent = r.domain;
      name.title = r.domain;
      var meta = document.createElement("span");
      meta.className = "meta";
      if (r.resolved) {
        meta.textContent = (r.ips && r.ips.length ? r.ips[0] : "") +
          (r.ips && r.ips.length > 1 ? " +" + (r.ips.length - 1) : "");
      } else {
        meta.textContent = "不可解析";
      }
      item.appendChild(box);
      item.appendChild(name);
      item.appendChild(meta);
      discoverListEl.appendChild(item);
    });
    refreshDiscoverState();
  }

  discoverAll.onchange = function () {
    var checked = discoverAll.checked;
    discovered.forEach(function (r) { if (r.resolved) r.checked = checked; });
    renderDiscovered();
  };

  discoverBtn.onclick = function () {
    var raw = discoverInput.value.trim();
    if (!raw) {
      discoverMsg.textContent = "请先输入主域名，如 github.com";
      discoverInput.focus();
      return;
    }
    raw = raw.replace(/^[a-zA-Z]+:\/\//, "").replace(/\/.*$/, "").toLowerCase();
    discoverBtn.disabled = true;
    discoverMsg.textContent = "正在发现 " + raw + " 的相关域名...";
    discovered = [];
    renderDiscovered();
    fetch("/api/expand", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: raw, sources: ["ct", "wordlist", "rules"] })
    }).then(function (r) { return r.json(); })
      .then(function (j) {
        discoverBtn.disabled = false;
        if (!j.ok) {
          discoverMsg.textContent = "获取失败: " + (j.error || "未知错误");
          return;
        }
        discovered = (j.results || []).map(function (r) {
          return { domain: r.domain, resolved: !!r.resolved, ips: r.ips || [], checked: !!r.resolved };
        }).sort(function (a, b) {
          if (a.resolved !== b.resolved) return a.resolved ? -1 : 1;
          return a.domain < b.domain ? -1 : (a.domain > b.domain ? 1 : 0);
        });
        renderDiscovered();
        var resolvedCount = discovered.filter(function (r) { return r.resolved; }).length;
        discoverToggle.disabled = discovered.length === 0;
        discoverMsg.textContent = "发现 " + discovered.length + " 个相关域名，" +
          resolvedCount + " 个可解析，已默认勾选可解析项。";
        if (discovered.length > 0) openDropdown(true);
      })
      .catch(function (e) {
        discoverBtn.disabled = false;
        discoverMsg.textContent = "请求失败: " + e;
      });
  };
  discoverInput.addEventListener("keydown", function (e) {
    if (e.key === "Enter") {
      e.preventDefault();
      discoverBtn.click();
    }
  });

  discoverAdd.onclick = function () {
    var names = checkedDomains();
    if (names.length === 0) return;
    try {
      syncFormIfNeeded();
    } catch (e) {
      discoverMsg.textContent = e.message;
      return;
    }
    var cfgObj;
    try {
      cfgObj = JSON.parse(cfg.value);
    } catch (e) {
      discoverMsg.textContent = "配置解析失败，请先修正 domains.json 再添加";
      return;
    }
    if (!Array.isArray(cfgObj.domains)) cfgObj.domains = [];
    var existing = new Set(cfgObj.domains.map(function (d) { return d && d.name; }));
    var added = 0;
    names.forEach(function (n) {
      if (!existing.has(n)) {
        cfgObj.domains.push({ name: n, expand: false });
        existing.add(n);
        added++;
      }
    });
    if (added > 0) {
      cfg.value = JSON.stringify(cfgObj, null, 2);
      if (cfgTab === "form") fillForm(cfg.value);
      discoverMsg.textContent = "已添加 " + added + " 个域名到配置，请点下方「保存并生效」写入";
      cfgMsg.textContent = "待保存：" + added + " 个新域名";
      openDropdown(false);
    } else {
      discoverMsg.textContent = "勾选的域名都已存在于配置中";
    }
  };

  // 按主域名分组：点击分组标题展开该分类下的全部域名
  var searchInput = document.getElementById("search");
  var statusFilter = document.getElementById("statusFilter");
  var tbody = document.querySelector("tbody");
  var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
  var filteredRows = [];
  var groups = [];
  var multiSuffix = {
    "com.cn": 1, "net.cn": 1, "org.cn": 1, "gov.cn": 1, "edu.cn": 1,
    "co.uk": 1, "org.uk": 1, "ac.uk": 1,
    "com.hk": 1, "com.tw": 1, "com.sg": 1, "com.au": 1, "com.br": 1,
    "co.jp": 1, "co.kr": 1, "co.in": 1, "co.nz": 1, "co.za": 1,
    "com.ru": 1, "com.mx": 1
  };

  function baseDomain(name) {
    var parts = String(name || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    var lastTwo = parts.slice(-2).join(".");
    if (multiSuffix[lastTwo]) return parts.slice(-3).join(".");
    return lastTwo;
  }

  function buildGroups() {
    var map = {};
    rows.forEach(function (tr) {
      var base = baseDomain(tr.dataset.name);
      if (!map[base]) {
        map[base] = { base: base, rows: [], open: false, visible: [] };
        groups.push(map[base]);
      }
      map[base].rows.push(tr);
    });
    groups.sort(function (a, b) { return a.base < b.base ? -1 : (a.base > b.base ? 1 : 0); });
    tbody.innerHTML = "";
    groups.forEach(function (g) {
      g.rows.sort(function (a, b) {
        return a.dataset.name < b.dataset.name ? -1 : (a.dataset.name > b.dataset.name ? 1 : 0);
      });
      var head = document.createElement("tr");
      head.className = "group-row";
      var cell = document.createElement("td");
      cell.colSpan = 7;
      var wrap = document.createElement("div");
      wrap.className = "group-head";

      var toggle = document.createElement("button");
      toggle.type = "button";
      toggle.className = "group-toggle";
      var caret = document.createElement("span");
      caret.className = "caret";
      caret.textContent = "▶";
      var groupName = document.createElement("span");
      groupName.className = "group-name";
      groupName.textContent = g.base;
      var count = document.createElement("span");
      count.className = "group-count";
      var ok = document.createElement("span");
      ok.className = "group-ok";
      toggle.appendChild(caret);
      toggle.appendChild(groupName);
      toggle.appendChild(count);
      toggle.appendChild(ok);

      var selectLabel = document.createElement("label");
      selectLabel.className = "group-select";
      var groupCheck = document.createElement("input");
      groupCheck.type = "checkbox";
      selectLabel.appendChild(groupCheck);
      selectLabel.appendChild(document.createTextNode(" 全选本组"));

      wrap.appendChild(toggle);
      wrap.appendChild(selectLabel);
      cell.appendChild(wrap);
      head.appendChild(cell);
      tbody.appendChild(head);
      g.rows.forEach(function (tr) {
        tr.classList.add("domain-row", "table-row-hidden");
        tbody.appendChild(tr);
      });

      g.head = head;
      g.caret = caret;
      g.count = count;
      g.ok = ok;
      g.check = groupCheck;

      toggle.onclick = function () {
        g.open = !g.open;
        head.classList.toggle("open", g.open);
        caret.textContent = g.open ? "▼" : "▶";
        applyFilter();
      };
      groupCheck.onchange = function () {
        g.visible.forEach(function (tr) {
          var c = tr.querySelector(".row-check");
          if (c) c.checked = groupCheck.checked;
        });
        updateSelection();
      };
    });
  }

  function applyFilter() {
    var kw = searchInput.value.trim().toLowerCase();
    var st = statusFilter.value;
    filteredRows = [];
    groups.forEach(function (g) {
      var visible = g.rows.filter(function (tr) {
        var name = (tr.dataset.name || "").toLowerCase();
        var ip = (tr.dataset.ip || "").toLowerCase();
        var reason = (tr.dataset.reason || "").toLowerCase();
        var validated = tr.dataset.status === "true";
        var match = !kw || name.indexOf(kw) >= 0 || ip.indexOf(kw) >= 0 || reason.indexOf(kw) >= 0;
        var statusMatch = st === "all" || (st === "ok" && validated) || (st === "fail" && !validated);
        return match && statusMatch;
      });
      g.visible = visible;
      filteredRows = filteredRows.concat(visible);
      g.head.classList.toggle("table-row-hidden", visible.length === 0);
      if (kw && visible.length > 0) {
        g.open = true;
        g.head.classList.add("open");
        g.caret.textContent = "▼";
      }
      g.rows.forEach(function (tr) {
        tr.classList.toggle("table-row-hidden", !g.open || visible.indexOf(tr) < 0);
      });
      var okCount = visible.filter(function (tr) { return tr.dataset.status === "true"; }).length;
      g.count.textContent = visible.length + " 个域名";
      g.ok.textContent = okCount + " 正常";
      g.ok.className = "group-ok" + (visible.length - okCount > 0 ? " has-bad" : "");
    });
    updateSelection();
  }

  searchInput.addEventListener("input", applyFilter);
  statusFilter.addEventListener("change", applyFilter);

  // 表格勾选与批量删除
  var selectAll = document.getElementById("selectAll");
  var selCount = document.getElementById("selCount");
  var batchDelete = document.getElementById("batchDelete");
  var expandAllBtn = document.getElementById("expandAll");
  var collapseAllBtn = document.getElementById("collapseAll");

  function rowChecks() {
    return Array.prototype.slice.call(document.querySelectorAll(".row-check"));
  }
  function selectedNames() {
    return rowChecks().filter(function (c) { return c.checked; })
      .map(function (c) { return c.value; });
  }
  function updateSelection() {
    var total = selectedNames().length;
    selCount.textContent = "已选 " + total + " 个域名";
    batchDelete.disabled = total === 0;
    selectAll.checked = filteredRows.length > 0 && filteredRows.every(function (tr) {
      var c = tr.querySelector(".row-check");
      return c && c.checked;
    });
    selectAll.indeterminate = !selectAll.checked && filteredRows.some(function (tr) {
      var c = tr.querySelector(".row-check");
      return c && c.checked;
    });
    groups.forEach(function (g) {
      var checkedCount = g.visible.filter(function (tr) {
        var c = tr.querySelector(".row-check");
        return c && c.checked;
      }).length;
      g.check.disabled = g.visible.length === 0;
      g.check.checked = g.visible.length > 0 && checkedCount === g.visible.length;
      g.check.indeterminate = checkedCount > 0 && checkedCount < g.visible.length;
    });
  }
  selectAll.onchange = function () {
    filteredRows.forEach(function (tr) {
      var c = tr.querySelector(".row-check");
      if (c) c.checked = selectAll.checked;
    });
    updateSelection();
  };
  document.querySelectorAll(".row-check").forEach(function (c) {
    c.onchange = updateSelection;
  });
  expandAllBtn.onclick = function () {
    groups.forEach(function (g) {
      g.open = true;
      g.head.classList.add("open");
      g.caret.textContent = "▼";
    });
    applyFilter();
  };
  collapseAllBtn.onclick = function () {
    groups.forEach(function (g) {
      g.open = false;
      g.head.classList.remove("open");
      g.caret.textContent = "▶";
    });
    applyFilter();
  };
  batchDelete.onclick = function () {
    var names = selectedNames();
    if (names.length === 0) return;
    if (!confirm("确定从配置中删除选中的 " + names.length + " 个域名？删除后需点「保存并生效」。")) return;
    try {
      syncFormIfNeeded();
    } catch (e) {
      msg.textContent = e.message;
      return;
    }
    var cfgObj;
    try {
      cfgObj = JSON.parse(cfg.value);
    } catch (e) {
      msg.textContent = "配置解析失败: " + e;
      return;
    }
    var remove = new Set(names);
    var before = Array.isArray(cfgObj.domains) ? cfgObj.domains.length : 0;
    cfgObj.domains = (cfgObj.domains || []).filter(function (d) {
      return !(d && remove.has(d.name));
    });
    var removed = before - cfgObj.domains.length;
    cfg.value = JSON.stringify(cfgObj, null, 2);
    if (cfgTab === "form") fillForm(cfg.value);
    cfgMsg.textContent = "已从配置移除 " + removed + " 个域名，请点「保存并生效」写入";
    msg.textContent = "已移除 " + removed + " 个域名";
    var details = document.querySelector("details");
    if (details) {
      details.open = true;
      details.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    updateSelection();
  };

  buildGroups();
  applyFilter();

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

  // 单独刷新域名（实际触发一轮全量探测，按钮仅作快捷入口）
  document.querySelectorAll(".refresh-btn").forEach(function(rowBtn) {
    rowBtn.onclick = function() {
      var domain = rowBtn.dataset.domain;
      rowBtn.disabled = true;
      rowBtn.textContent = "刷新中...";
      msg.textContent = "正在刷新 " + domain + " 等域名，请稍等";
      startRefresh(msg, function() {
        rowBtn.disabled = false;
        rowBtn.textContent = "刷新";
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
