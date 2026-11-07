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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsquery"
	"hosts-optimizer/internal/expand"
	"hosts-optimizer/internal/history"
	"hosts-optimizer/internal/logbuf"
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
	stateMu                                   sync.RWMutex
	history                                   history.Store
	version                                   string

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
	Domains          []string   `json:"domains,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// New 初始化目录、CA 池、状态，并尝试从磁盘恢复上一轮产物。
func New(rt *config.Runtime, version string) (*App, error) {
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
	hs, err := history.Open(filepath.Join(rt.StateDir, "history"), rt.Config.Defaults.HistoryRetentionMonths)
	if err != nil {
		log.Printf("历史存储不可用（服务继续运行）: %v", err)
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
		history:      hs,
		version:      version,
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

// doRound 执行一轮全量探测。
func (a *App) doRound(ctx context.Context) (int, error) {
	return a.doRoundFor(ctx, nil)
}

// doRoundFor 执行一轮；only 非空时只刷新指定域名，并把结果合并回现有快照。
// roundMu 保证定时器与 /refresh 不会并发探测。
// 每轮重新读取 domains.json，因此手动增删域名后下一轮自动生效，无需重启。
func (a *App) doRoundFor(ctx context.Context, only map[string]bool) (int, error) {
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
	disabled := make(map[string]bool, len(rt.Config.Domains))
	for _, dom := range rt.Config.Domains {
		t := rt.Config.Resolve(dom)
		if t.Disabled {
			disabled[t.Name] = true
			continue
		}
		if seen[t.Name] {
			continue
		}
		seen[t.Name] = true
		targets = append(targets, t)
	}
	// 展开放在配置域名之后，确保用户在 domains.json 里的显式配置优先。
	// 定向刷新不重新展开，避免为了几个域名再跑一次子域名发现。
	if only == nil {
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
	} else {
		for name := range only {
			if disabled[name] {
				delete(only, name)
			}
		}
		targets = selectTargets(targets, only, d)
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
		a.stateMu.Lock()
		dec := a.state.Decide(t.Name, cands, d.HysteresisPercent, d.HysteresisRounds, time.Now())
		a.stateMu.Unlock()
		entries = append(entries, output.Entry{
			Name: t.Name, IP: dec.IP, LatencyMS: dec.LatencyMS,
			Reason: dec.Reason, Validated: dec.Validated,
			Candidates: len(ips), SuppressAAAA: t.SuppressAAAA,
		})
		log.Printf("[%s] 候选 %d → 校验通过 %d → 生效 %q（%s）", t.Name, len(ips), len(results), dec.IP, dec.Reason)
	}

	refreshed := entries
	if only != nil {
		a.mu.RLock()
		var existing []output.StatusDomain
		if a.snap != nil {
			existing = a.snap.Status.Domains
		}
		a.mu.RUnlock()
		entries = mergeEntries(existing, refreshed)
	}

	now := time.Now()
	a.appendHistory(refreshed, now, fmt.Sprintf("r%d", started.UnixNano()))
	round := output.RoundInfo{
		StartedAt: started, FinishedAt: now, OK: true,
		ScheduleMinutes: d.ScheduleMinutes,
	}
	a.stateMu.Lock()
	saveErr := a.state.Save(a.statePath, now)
	a.stateMu.Unlock()
	if saveErr != nil {
		log.Printf("保存状态失败: %v", saveErr)
	}
	snap, err := output.Build(entries, now, round)
	if err != nil {
		return d.ScheduleMinutes, err
	}
	if err := a.writeSnapshot(snap); err != nil {
		return d.ScheduleMinutes, err
	}
	a.mu.Lock()
	a.snap = snap
	a.mu.Unlock()
	log.Printf("本轮完成：%d/%d 个域名生效，产物已写入 %s", snap.Status.ActiveCount, len(entries), filepath.Dir(a.hostsPath))
	return d.ScheduleMinutes, nil
}

// selectTargets 过滤出本次要刷新的目标；配置里不存在的子域名按默认参数补齐。
func selectTargets(all []config.Target, only map[string]bool, d config.Defaults) []config.Target {
	out := make([]config.Target, 0, len(only))
	found := make(map[string]bool, len(only))
	for _, t := range all {
		if only[t.Name] {
			out = append(out, t)
			found[t.Name] = true
		}
	}
	missing := make([]string, 0, len(only))
	for name := range only {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		out = append(out, config.Target{
			Name: name, SNI: name, Port: d.ProbePort, ExpectStatus: d.ExpectStatus,
		})
	}
	return out
}

// statusToEntries 把状态快照还原成可重新生成产物的条目。
func statusToEntries(domains []output.StatusDomain) []output.Entry {
	out := make([]output.Entry, 0, len(domains))
	for _, s := range domains {
		out = append(out, output.Entry{
			Name: s.Name, IP: s.IP, LatencyMS: s.LatencyMS, Reason: s.Reason,
			Validated: s.Validated, Candidates: s.Candidates, SuppressAAAA: s.SuppressAAAA,
		})
	}
	return out
}

// mergeEntries 用本轮刷新的结果覆盖已有状态，其余域名保持不变。
func mergeEntries(existing []output.StatusDomain, refreshed []output.Entry) []output.Entry {
	base := statusToEntries(existing)
	byName := make(map[string]output.Entry, len(base)+len(refreshed))
	order := make([]string, 0, len(base)+len(refreshed))
	for _, e := range base {
		byName[e.Name] = e
		order = append(order, e.Name)
	}
	for _, e := range refreshed {
		if _, ok := byName[e.Name]; !ok {
			order = append(order, e.Name)
		}
		byName[e.Name] = e
	}
	out := make([]output.Entry, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// writeSnapshot 原子写入三份产物；整轮全灭且已有旧产物时保留旧文件。
func (a *App) writeSnapshot(snap *output.Snapshot) error {
	return a.writeSnapshotMode(snap, false)
}

// writeSnapshotForce 强制写入三份产物，用于用户显式禁用/删除等主动操作。
func (a *App) writeSnapshotForce(snap *output.Snapshot) error {
	return a.writeSnapshotMode(snap, true)
}

func (a *App) writeSnapshotMode(snap *output.Snapshot, force bool) error {
	if snap.Ready || force {
		if err := util.AtomicWrite(a.hostsPath, snap.Hosts); err != nil {
			return err
		}
		if err := util.AtomicWrite(a.aghPath, snap.AGH); err != nil {
			return err
		}
	} else if !util.Exists(a.hostsPath) {
		// 首次启动且还没有任何有效 IP：写仅含注释的文件，让端点可访问。
		// 之后若整轮全灭，保留上一轮产物，绝不覆盖。
		if err := util.AtomicWrite(a.hostsPath, snap.Hosts); err != nil {
			return err
		}
		if err := util.AtomicWrite(a.aghPath, snap.AGH); err != nil {
			return err
		}
	}
	return util.AtomicWrite(a.statusPath, snap.StatusBytes)
}

// appendHistory 写入一组探测记录；失败只告警，不影响本轮产物。
func (a *App) appendHistory(entries []output.Entry, at time.Time, roundID string) {
	if a.history == nil || len(entries) == 0 {
		return
	}
	records := make([]history.Record, 0, len(entries))
	for _, e := range entries {
		records = append(records, history.Record{
			Time: at, RoundID: roundID, Domain: e.Name, Group: history.BaseDomain(e.Name),
			IP: e.IP, LatencyMS: e.LatencyMS, Candidates: e.Candidates,
			Validated: e.Validated > 0, Reason: e.Reason,
		})
	}
	if err := a.history.Append(records); err != nil {
		log.Printf("写入历史失败: %v", err)
	}
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
	case "/api/logs":
		a.handleLogs(w, r)
	case "/api/history":
		a.handleHistory(w, r)
	case "/api/candidates":
		a.handleCandidates(w, r)
	case "/api/switch":
		a.handleSwitch(w, r)
	case "/api/refresh-agh":
		a.handleRefreshAGH(w, r)
	case "/api/disable":
		a.handleDisable(w, r)
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
	var req struct {
		Domains []string `json:"domains"`
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析请求失败: " + err.Error()})
			return
		}
	}
	names := normalizeDomainNames(req.Domains)
	taskID, reused := a.startRefresh(names)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "task_id": taskID, "reused": reused, "domains": names,
	})
}

func normalizeDomainNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, n := range in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// startRefresh 在后台启动一轮探测；已有任务在跑时直接复用，避免重复排队。
func (a *App) startRefresh(domains []string) (string, bool) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if a.refreshTask != nil && a.refreshTask.State == refreshRunning {
		return a.refreshTask.ID, true
	}
	task := &refreshTask{
		ID:        fmt.Sprintf("r%d", time.Now().UnixNano()),
		State:     refreshRunning,
		StartedAt: time.Now(),
		Domains:   domains,
	}
	a.refreshTask = task
	go a.runRefresh(task, domains)
	return task.ID, false
}

// runRefresh 执行后台轮次并回填任务状态。
// 使用独立 context：请求结束后探测不应被取消，各阶段仍有自身的超时控制。
func (a *App) runRefresh(task *refreshTask, domains []string) {
	var minutes int
	var err error
	if len(domains) == 0 {
		minutes, err = a.doRound(context.Background())
	} else {
		only := make(map[string]bool, len(domains))
		for _, name := range domains {
			only[name] = true
		}
		minutes, err = a.doRoundFor(context.Background(), only)
	}
	if err == nil {
		if n, aghErr := a.rebuildAGH(time.Now()); aghErr != nil {
			log.Printf("同步 AGH 订阅失败: %v", aghErr)
		} else {
			log.Printf("AGH 订阅已同步（%d 字节）", n)
		}
	}
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
		"next_round_minutes": snap.NextRoundMinutes, "domains": snap.Domains, "error": snap.Error,
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
		parsed, err := config.Parse(body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if err := util.AtomicWrite(a.configPath, body); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "写入配置失败: " + err.Error()})
			return
		}
		log.Printf("配置已更新: %s（%d 字节）", a.configPath, len(body))
		// 保存后立即把禁用域名从产物中移除，避免页面显示禁用但订阅仍在生效。
		disabledNames := make(map[string]bool)
		for _, d := range parsed.Domains {
			if d.Disabled {
				disabledNames[strings.ToLower(strings.TrimSpace(d.Name))] = true
			}
		}
		if len(disabledNames) > 0 {
			if err := a.removeFromSnapshot(disabledNames); err != nil {
				log.Printf("移除禁用域名失败: %v", err)
			}
		}
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

// handleLogs 返回内存中的运行日志；after 用于增量拉取，limit 限制单次条数。
func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET"})
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries := logbuf.Default.Snapshot(after, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "entries": entries, "last_seq": logbuf.Default.LastSeq(),
	})
}

// handleHistory 查询探测历史；支持 domain/group/from/to/limit。
func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET"})
		return
	}
	if a.history == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "历史存储不可用"})
		return
	}
	q := r.URL.Query()
	from, err := parseHistoryTime(q.Get("from"), true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	to, err := parseHistoryTime(q.Get("to"), false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	limit := 500
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "limit 必须是正整数"})
			return
		}
		if n > 5000 {
			n = 5000
		}
		limit = n
	}
	records, err := a.history.Query(history.Filter{
		Domain: strings.TrimSpace(q.Get("domain")),
		Group:  strings.TrimSpace(q.Get("group")),
		From:   from, To: to, Limit: limit,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "查询历史失败: " + err.Error()})
		return
	}
	if records == nil {
		records = []history.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "records": records, "count": len(records)})
}

func parseHistoryTime(v string, isFrom bool) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", v, time.Local); err == nil {
		if !isFrom {
			t = t.Add(24*time.Hour - time.Nanosecond)
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("时间格式应为 RFC3339 或 YYYY-MM-DD: %q", v)
}

// handleCandidates 返回某域名最近一轮通过校验的全部候选 IP 与延迟。
func (a *App) handleCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET"})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain")))
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "domain 不能为空"})
		return
	}
	a.stateMu.RLock()
	st := a.state.Domains[domain]
	current := ""
	candidates := []store.Candidate{}
	if st != nil {
		current = st.IP
		candidates = append(candidates, st.Candidates...)
	}
	a.stateMu.RUnlock()
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "没有该域名的探测记录"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "domain": domain, "current_ip": current, "candidates": candidates,
	})
}

// handleSwitch 手动把某个域名切换到候选列表中的指定 IP。
func (a *App) handleSwitch(w http.ResponseWriter, r *http.Request) {
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
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析请求失败: " + err.Error()})
		return
	}
	domain := strings.ToLower(strings.TrimSpace(req.Domain))
	ip := strings.TrimSpace(req.IP)
	if domain == "" || ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "domain/ip 不能为空"})
		return
	}
	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "ip 不是合法地址"})
		return
	}

	a.roundMu.Lock()
	defer a.roundMu.Unlock()
	now := time.Now()

	a.stateMu.Lock()
	st := a.state.Domains[domain]
	var chosen store.Candidate
	found := false
	if st != nil {
		for _, c := range st.Candidates {
			if c.IP == ip {
				chosen, found = c, true
				break
			}
		}
	}
	if st == nil || !found {
		a.stateMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "该 IP 不在最近一轮的候选列表中，请先刷新该域名"})
		return
	}
	st.IP = ip
	st.LatencyMS = chosen.LatencyMS
	st.LastSwitch = now
	st.ChallengerIP = ""
	st.ChallengerWins = 0
	st.ConsecutiveFailures = 0
	saveErr := a.state.Save(a.statePath, now)
	candidateCount := len(st.Candidates)
	a.stateMu.Unlock()
	if saveErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "保存状态失败: " + saveErr.Error()})
		return
	}

	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	if snap == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "服务正在初始化，请稍后重试"})
		return
	}
	entries := statusToEntries(snap.Status.Domains)
	replaced := false
	for i := range entries {
		if entries[i].Name == domain {
			entries[i].IP = ip
			entries[i].LatencyMS = chosen.LatencyMS
			entries[i].Validated = 1
			entries[i].Reason = "手动切换"
			replaced = true
			break
		}
	}
	if !replaced {
		entries = append(entries, output.Entry{
			Name: domain, IP: ip, LatencyMS: chosen.LatencyMS,
			Validated: 1, Reason: "手动切换", Candidates: candidateCount,
		})
	}
	round := output.RoundInfo{
		StartedAt: snap.Status.GeneratedAt, FinishedAt: now, OK: true,
		ScheduleMinutes: snap.Status.ScheduleMinutes,
	}
	built, err := output.Build(entries, now, round)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "生成产物失败: " + err.Error()})
		return
	}
	if err := a.writeSnapshot(built); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "写入产物失败: " + err.Error()})
		return
	}
	a.mu.Lock()
	a.snap = built
	a.mu.Unlock()
	a.appendHistory([]output.Entry{{
		Name: domain, IP: ip, LatencyMS: chosen.LatencyMS,
		Validated: 1, Reason: "手动切换", Candidates: candidateCount,
	}}, now, fmt.Sprintf("r%d", now.UnixNano()))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "domain": domain, "ip": ip, "latency_ms": chosen.LatencyMS,
	})
}

var (
	errNoSnapshot = errors.New("服务正在初始化，请稍后重试")
	errNoValidIP  = errors.New("暂无有效 IP，未刷新 AGH 规则")
)

// rebuildAGH 用当前快照重写 agh.txt，不重新探测。调用方无需持有 roundMu。
func (a *App) rebuildAGH(now time.Time) (int, error) {
	a.roundMu.Lock()
	defer a.roundMu.Unlock()
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	if snap == nil {
		return 0, errNoSnapshot
	}
	entries := statusToEntries(snap.Status.Domains)
	round := output.RoundInfo{
		StartedAt: snap.Status.GeneratedAt, FinishedAt: now, OK: true,
		ScheduleMinutes: snap.Status.ScheduleMinutes,
	}
	built, err := output.Build(entries, now, round)
	if err != nil {
		return 0, fmt.Errorf("生成 AGH 规则失败: %w", err)
	}
	if !built.Ready {
		return 0, errNoValidIP
	}
	if err := util.AtomicWrite(a.aghPath, built.AGH); err != nil {
		return 0, fmt.Errorf("写入 AGH 规则失败: %w", err)
	}
	a.mu.Lock()
	if a.snap != nil {
		a.snap.AGH = built.AGH
		a.snap.AGHETag = built.AGHETag
		a.snap.Modified = now
	}
	a.mu.Unlock()
	return len(built.AGH), nil
}

// handleRefreshAGH 只用当前快照重新生成 agh.txt，不重新探测。
func (a *App) handleRefreshAGH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	n, err := a.rebuildAGH(time.Now())
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNoSnapshot) {
			code = http.StatusServiceUnavailable
		} else if errors.Is(err, errNoValidIP) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": n})
}

// handleDisable 批量启用/禁用域名，立即写回配置并从产物中移除被禁用的域名。
// 请求体：{"names":["a.com"],"disabled":true}，或 {"group":"github.com","disabled":true}。
func (a *App) handleDisable(w http.ResponseWriter, r *http.Request) {
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
		Names    []string `json:"names"`
		Group    string   `json:"group"`
		Disabled bool     `json:"disabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析请求失败: " + err.Error()})
		return
	}
	group := strings.ToLower(strings.TrimSpace(req.Group))
	wanted := make(map[string]bool, len(req.Names))
	for _, n := range normalizeDomainNames(req.Names) {
		wanted[n] = true
	}
	if group == "" && len(wanted) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "names 或 group 至少提供一个"})
		return
	}

	a.roundMu.Lock()
	defer a.roundMu.Unlock()

	raw, err := os.ReadFile(a.configPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取配置失败: " + err.Error()})
		return
	}
	// 用 map 修改，保留用户原有字段与格式，避免把缺省字段写成零值。
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "解析配置失败: " + err.Error()})
		return
	}
	if root == nil {
		root = map[string]any{}
	}
	domainsRaw, _ := root["domains"].([]any)

	changed := 0
	affected := make(map[string]bool)
	for _, item := range domainsRaw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rawName, _ := m["name"].(string)
		name := strings.ToLower(strings.TrimSpace(rawName))
		if name == "" {
			continue
		}
		match := wanted[name]
		if !match && group != "" {
			match = history.BaseDomain(name) == group
		}
		if !match {
			continue
		}
		affected[name] = true
		cur, _ := m["disabled"].(bool)
		if cur != req.Disabled {
			if req.Disabled {
				m["disabled"] = true
			} else {
				delete(m, "disabled")
			}
			changed++
		}
	}
	if changed == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": 0, "names": len(affected)})
		return
	}
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "序列化配置失败: " + err.Error()})
		return
	}
	out = append(out, '\n')
	if _, err := config.Parse(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "配置校验失败: " + err.Error()})
		return
	}
	if err := util.AtomicWrite(a.configPath, out); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "写入配置失败: " + err.Error()})
		return
	}
	log.Printf("已%s %d 个域名（配置已更新）", map[bool]string{true: "禁用", false: "启用"}[req.Disabled], changed)

	if req.Disabled {
		if err := a.removeFromSnapshot(affected); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": changed, "names": len(affected)})
}

// removeFromSnapshot 从当前快照与产物中移除指定域名，不触发重新探测。
func (a *App) removeFromSnapshot(names map[string]bool) error {
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	if snap == nil {
		return nil
	}
	entries := statusToEntries(snap.Status.Domains)
	kept := entries[:0]
	for _, e := range entries {
		if names[e.Name] {
			continue
		}
		kept = append(kept, e)
	}
	now := time.Now()
	round := output.RoundInfo{
		StartedAt: snap.Status.GeneratedAt, FinishedAt: now, OK: true,
		ScheduleMinutes: snap.Status.ScheduleMinutes,
	}
	built, err := output.Build(kept, now, round)
	if err != nil {
		return fmt.Errorf("生成产物失败: %w", err)
	}
	if err := a.writeSnapshotForce(built); err != nil {
		return fmt.Errorf("写入产物失败: %w", err)
	}
	a.mu.Lock()
	a.snap = built
	a.mu.Unlock()
	return nil
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
<html lang="zh-CN"><head><meta charset="utf-8"><title>Hosts 优选订阅</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--line:#e5e8ee;--text:#1f2937;--muted:#6b7280;--accent:#2563eb;--accent-dark:#1d4ed8;--danger:#dc2626;--ok:#16a34a;--surface-2:#f8fafc;--radius:14px;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;--sans:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei","Noto Sans CJK SC",system-ui,sans-serif}
*{box-sizing:border-box}
body{font-family:var(--sans);background:var(--bg);color:var(--text);max-width:1180px;margin:0 auto;padding:30px 20px 56px;line-height:1.65;font-size:15px;letter-spacing:.01em;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
.page-head{display:flex;align-items:center;gap:14px;margin:2px 0 18px}
.logo{width:46px;height:46px;flex:0 0 auto;display:block;filter:drop-shadow(0 2px 6px rgba(30,58,138,.25))}
.logo svg{width:100%;height:100%;display:block}
h1{font-size:26px;font-weight:700;letter-spacing:-.01em;margin:0 0 4px;line-height:1.25}
.sub{color:var(--muted);font-size:13px;margin:0;line-height:1.5;font-variant-numeric:tabular-nums}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;margin:16px 0;box-shadow:0 1px 2px rgba(16,24,40,.04)}
table{border-collapse:collapse;width:100%;font-size:14px;font-variant-numeric:tabular-nums}
th,td{border-bottom:1px solid var(--line);padding:12px;text-align:left;vertical-align:middle}
th{background:#f8fafc;font-weight:600;color:#4b5563;white-space:nowrap;font-size:12.5px;letter-spacing:.04em}
tbody tr:hover{background:#f9fafb}
tbody td:nth-child(2),tbody td:nth-child(3){font-family:var(--mono);font-size:13.5px}
tbody tr:last-child td{border-bottom:none}
tbody td:nth-child(5){white-space:nowrap}
code{background:#eef2f7;padding:2px 6px;border-radius:5px;font-size:12.5px;font-family:var(--mono)}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
button{cursor:pointer;padding:8px 16px;border:1px solid #d7dce5;border-radius:8px;background:#fff;color:#1f2937;font-size:13.5px;font-weight:500;font-family:inherit;line-height:1.4;transition:background .15s,border-color .15s,box-shadow .15s}
button:hover{background:#f3f4f6;border-color:#c3c9d4}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:2px solid rgba(37,99,235,.35);outline-offset:1px}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
button.primary:hover{background:var(--accent-dark);border-color:var(--accent-dark)}
button.danger{background:#fff;color:var(--danger);border-color:#f0b4b4}
button.danger:hover{background:#fef2f2;border-color:var(--danger)}
input[type=text],input[type=number],select{padding:8px 11px;border:1px solid #d7dce5;border-radius:8px;font-size:13.5px;font-family:inherit;background:#fff;color:var(--text)}
#sub{flex:1 1 320px;min-width:200px;font-family:var(--mono)}
#msg{font-size:14px;color:var(--muted);min-width:180px}
#search{flex:1 1 240px;min-width:180px}
#statusFilter{background:#fff}
details{margin:16px 0 0}
summary{cursor:pointer;font-weight:600;padding:6px 0;color:#111827;font-size:15px}
summary::marker{color:var(--accent)}
.summary-meta{font-weight:400;font-size:13px;color:var(--muted);margin-left:6px;font-variant-numeric:tabular-nums}
#domainListDetails>summary{margin-bottom:10px}
.hint{color:var(--muted);font-size:13px;margin:8px 0}
#cfg{width:100%;min-height:260px;font-family:var(--mono);font-size:12.5px;line-height:1.6;padding:12px;border:1px solid #d7dce5;border-radius:8px;resize:vertical;background:#fbfcfe}
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
.latency-btn{padding:0;border:none;background:transparent;color:var(--text);font-size:14px;font-family:inherit;text-decoration:underline dotted;text-underline-offset:3px;cursor:pointer}
.latency-btn:hover{background:transparent;color:var(--accent)}
.switch-btn{padding:4px 12px;font-size:12px}
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
.dropdown-item .domain{font-family:var(--mono);color:#111827;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.dropdown-item .meta{color:var(--muted);font-size:12px;white-space:nowrap}
.dropdown-empty{padding:18px 12px;text-align:center;color:var(--muted);font-size:13px}
.cfg-tabs{display:inline-flex;gap:4px;padding:3px;background:#eef2f7;border-radius:9px;margin:10px 0 14px}
.cfg-tabs button{border:none;background:transparent;padding:6px 14px;font-size:13px;border-radius:7px}
.cfg-tabs button.active{background:#fff;color:var(--accent);box-shadow:0 1px 3px rgba(16,24,40,.12)}
.cfg-form{display:none}
.cfg-form.active{display:block}
.cfg-json-wrap{display:none}
.cfg-json-wrap.active{display:block}
.cfg-section{border:1px solid var(--line);border-radius:10px;margin:0 0 12px;background:var(--card);overflow:hidden}
.cfg-section>summary{position:relative;padding:12px 14px 12px 32px;font-size:13px;font-weight:600;color:var(--text);cursor:pointer;list-style:none;user-select:none}
.cfg-section>summary::-webkit-details-marker{display:none}
.cfg-section>summary::marker{content:""}
.cfg-section>summary::before{content:"▶";position:absolute;left:14px;top:13px;font-size:10px;color:var(--accent)}
.cfg-section[open]>summary::before{content:"▼"}
.cfg-section[open]>summary{border-bottom:1px solid var(--line);background:var(--surface-2)}
.cfg-body{padding:12px 14px 14px}
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
.domain-main .d-name{flex:1 1 240px;min-width:160px;font-family:var(--mono)}
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
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(17,24,39,.55);z-index:100;align-items:center;justify-content:center;padding:20px}
.modal-overlay.show{display:flex}
.modal{display:flex;flex-direction:column;background:var(--card,#fff);border:1px solid var(--line);border-radius:12px;padding:20px 22px;width:min(94vw,760px);max-height:84vh;overflow:hidden;box-shadow:0 24px 60px rgba(16,24,40,.35)}
.modal h3{margin:0 0 12px;font-size:16px;line-height:1.5;word-break:break-all;flex:0 0 auto}
.modal .progress{margin:0 0 10px;height:6px;flex:0 0 auto;background:#eef1f6;border-radius:3px;overflow:hidden}
.modal .progress-bar{height:100%;width:0%;background:var(--accent);transition:width .3s,background .3s}
.modal .modal-hint{margin:0 0 10px;font-size:13px;color:var(--muted);line-height:1.5;flex:0 0 auto;word-break:break-word}
.modal .result-list{flex:1 1 auto;min-height:140px;overflow:auto;border:1px solid var(--line);border-radius:10px;padding:6px;background:var(--surface-2)}
.modal .result-item{display:flex;align-items:flex-start;gap:10px;padding:9px 10px;border-radius:8px;font-size:13px}
.modal .result-item + .result-item{border-top:1px solid var(--line)}
.modal .result-item:hover{background:rgba(37,99,235,.06)}
.modal .result-dot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;margin-top:6px}
.modal .result-ok .result-dot{background:var(--ok)}
.modal .result-fail .result-dot{background:#ef4444}
.modal .result-main{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:4px}
.modal .result-line{display:flex;align-items:center;gap:8px;flex-wrap:wrap;min-width:0}
.modal .result-domain{font-family:var(--mono);color:var(--text);word-break:break-all;line-height:1.4}
.modal .result-source{font-size:11px;padding:1px 6px;border-radius:8px}
.modal .result-ips{color:var(--muted);font-size:12px;font-family:var(--mono);line-height:1.5;word-break:break-all;white-space:normal}
.modal .result-info{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:3px}
.modal .modal-empty{display:flex;flex-direction:column;align-items:center;gap:10px;padding:28px 16px;color:var(--muted);font-size:13px;text-align:center}
.modal-actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:flex-end;margin-top:14px;padding-top:14px;border-top:1px solid var(--line);flex:0 0 auto}
.table-row-hidden{display:none}
.group-row td{background:#f7f9fc;padding:0}
.group-row.open td{background:#eff4fb}
.group-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:6px 12px}
.group-toggle{display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid transparent;border-radius:8px;background:transparent;font-size:14px;font-weight:600;color:#111827}
.group-toggle:hover{background:#e8eef8;border-color:#d5deec}
.group-toggle .caret{width:14px;color:var(--accent);font-size:11px;text-align:center}
.group-name{font-family:var(--mono)}
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
:root[data-theme="dark"]{--bg:#0f1216;--card:#171c22;--line:#2a323c;--text:#e6e9ee;--muted:#9aa4b2;--accent:#60a5fa;--accent-dark:#3b82f6;--danger:#f87171;--ok:#34d399;--surface-2:#1d242c}
:root[data-theme="dark"] .card{box-shadow:0 1px 2px rgba(0,0,0,.35)}
:root[data-theme="dark"] th{background:#1d242c;color:#cbd5e1}
:root[data-theme="dark"] tbody tr:hover{background:#1f272f}
:root[data-theme="dark"] code{background:#2a333f}
:root[data-theme="dark"] button{background:#1b212a;border-color:#3a4453;color:#e6e9ee}
:root[data-theme="dark"] button:hover{background:#232b35;border-color:#4b5563}
:root[data-theme="dark"] button.primary{background:var(--accent);border-color:var(--accent);color:#0b1220}
:root[data-theme="dark"] button.primary:hover{background:var(--accent-dark);border-color:var(--accent-dark);color:#fff}
:root[data-theme="dark"] button.danger{background:#1b212a;border-color:#7f3b3b}
:root[data-theme="dark"] button.danger:hover{background:#2a1b1b;border-color:var(--danger)}
:root[data-theme="dark"] input[type=text],:root[data-theme="dark"] input[type=number],:root[data-theme="dark"] select{background:#12171d;border-color:#3a4453;color:var(--text)}
:root[data-theme="dark"] #statusFilter,:root[data-theme="dark"] #themeSel{background:#12171d}
:root[data-theme="dark"] summary{color:var(--text)}
:root[data-theme="dark"] #cfg{background:#12171d;border-color:#3a4453}
:root[data-theme="dark"] .status-fail{background:#f87171}
:root[data-theme="dark"] .badge{background:rgba(96,165,250,.16);color:#93c5fd}
:root[data-theme="dark"] .badge-ct{background:rgba(251,146,60,.16);color:#fdba74}
:root[data-theme="dark"] .badge-wl{background:rgba(52,211,153,.16);color:#6ee7b7}
:root[data-theme="dark"] .badge-rl{background:rgba(167,139,250,.16);color:#c4b5fd}
:root[data-theme="dark"] .discover{background:#131920;border-color:#3a4453}
:root[data-theme="dark"] .dropdown-panel{background:var(--card);box-shadow:0 12px 32px rgba(0,0,0,.5)}
:root[data-theme="dark"] .dropdown-head{background:#1d242c}
:root[data-theme="dark"] .dropdown-item{border-color:#232b35}
:root[data-theme="dark"] .dropdown-item:hover{background:#232b35}
:root[data-theme="dark"] .dropdown-item.disabled{background:#141a21}
:root[data-theme="dark"] .dropdown-item .domain{color:var(--text)}
:root[data-theme="dark"] .cfg-tabs{background:#232b35}
:root[data-theme="dark"] .cfg-tabs button.active{background:#2f3945;color:var(--accent)}
:root[data-theme="dark"] .field-grid label,:root[data-theme="dark"] .domain-main label{color:#b6c0cc}
:root[data-theme="dark"] .checks label{color:#cbd5e1}
:root[data-theme="dark"] .domain-item{background:var(--card)}
:root[data-theme="dark"] .domain-adv{background:#141a21}
:root[data-theme="dark"] .modal{background:var(--card);box-shadow:0 20px 50px rgba(0,0,0,.55)}
:root[data-theme="dark"] .modal .result-item:hover{background:#232b35}
:root[data-theme="dark"] .modal .result-domain{color:var(--text)}
:root[data-theme="dark"] .modal .progress{background:#232b35}
:root[data-theme="dark"] .group-row td{background:#1a222b}
:root[data-theme="dark"] .group-row.open td{background:#1f2a37}
:root[data-theme="dark"] .group-toggle{color:var(--text)}
:root[data-theme="dark"] .group-toggle:hover{background:#232b35;border-color:#3a4453}
:root[data-theme="dark"] .group-ok.has-bad{color:#fbbf24}
:root[data-theme="dark"] tr.domain-row td{background:var(--card)}
.log-tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:10px 0}
.log-tools label{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--muted);cursor:pointer;white-space:nowrap}
.log-tools input[type=checkbox]{width:15px;height:15px;accent-color:var(--accent);margin:0}
#logFilter{flex:1 1 240px;min-width:160px}
#logView{height:340px;overflow:auto;margin:0;padding:12px;background:var(--card);border:1px solid var(--line);border-radius:8px;font-family:var(--mono);font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-break:break-all;color:var(--text)}
#logView .log-line{display:block}
#logView .log-time{color:var(--muted);margin-right:8px}
#logState{font-size:13px;color:var(--muted)}
.mono{font-family:var(--mono)}
.about-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:10px 24px;margin:6px 0 14px}
.about-item{display:flex;gap:10px;align-items:baseline;font-size:13.5px;min-width:0}
.about-label{color:var(--muted);flex:0 0 auto;font-size:12.5px}
.about-value{color:var(--text);min-width:0;word-break:break-all;font-size:13px}
a.about-value{color:var(--accent);text-decoration:none}
a.about-value:hover{text-decoration:underline}
.about-block h4{margin:0 0 6px;font-size:13px;color:var(--text);font-weight:600}
.about-steps{margin:0;padding-left:20px;color:var(--muted);font-size:13px;line-height:1.85}
.about-steps code{font-size:12px}
.about-foot{margin-top:12px;color:var(--muted);font-size:12.5px;line-height:1.6}
.history-tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:10px 0}
#historyDomain{min-width:180px}
#historyRange{min-width:130px}
#historyState{font-size:13px;color:var(--muted)}
.trend-wrap{margin:6px 0 14px}
#trendChart{width:100%;height:220px;display:block}
.trend-grid{stroke:var(--line);stroke-width:1}
.trend-label{fill:var(--muted);font-size:11px}
.trend-line{fill:none;stroke:var(--accent);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.trend-dot{fill:var(--accent)}
.trend-area{fill:var(--accent);opacity:.10;stroke:none}
.history-table-wrap{max-height:320px;overflow:auto;border:1px solid var(--line);border-radius:8px}
.history-table{width:100%;font-size:13px}
.history-table th{position:sticky;top:0;z-index:1}
.history-table td,.history-table th{padding:8px 10px}
.history-empty{padding:16px;text-align:center;color:var(--muted);font-size:13px}
</style>
<script>
(function(){try{var m=localStorage.getItem("ho-theme")||"system";var d=m==="dark"||(m==="system"&&window.matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.setAttribute("data-theme",d?"dark":"light");}catch(e){}})();
</script>
</head><body>
<header class="page-head">
  <span class="logo" aria-hidden="true">
    <svg viewBox="0 0 48 48">
      <defs>
        <linearGradient id="hoLogoBg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#1e3a8a"/>
          <stop offset="1" stop-color="#4f46e5"/>
        </linearGradient>
      </defs>
      <rect width="48" height="48" rx="11" fill="url(#hoLogoBg)"/>
      <circle cx="24" cy="24" r="13" fill="none" stroke="#fff" stroke-width="2"/>
      <ellipse cx="24" cy="24" rx="6" ry="13" fill="none" stroke="#fff" stroke-width="1.5"/>
      <line x1="11" y1="24" x2="37" y2="24" stroke="#fff" stroke-width="1.5"/>
      <path d="M27 14 L20 26 h5 l-3 8 9-13 h-5 z" fill="#22c55e" stroke="#fff" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>
  </span>
  <div>
    <h1>Hosts 优选订阅</h1>
    <p class="sub">生成于 {{.GeneratedAt}} · 每 {{.ScheduleMinutes}} 分钟轮询 · 有效 {{.ActiveCount}}/{{.DomainCount}} 个域名</p>
  </div>
</header>

<div class="card">
<div class="bar">
<input id="sub" type="text" readonly>
<button id="copy" type="button">复制订阅地址</button>
<button id="refresh" type="button">刷新 AGH 规则</button>
<select id="statusFilter">
  <option value="all">全部</option>
  <option value="ok">正常</option>
  <option value="fail">失败</option>
  <option value="pending">待探测</option>
  <option value="disabled">已禁用</option>
</select>
<select id="themeSel" title="主题">
  <option value="system">跟随系统</option>
  <option value="light">浅色</option>
  <option value="dark">深色</option>
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
  <details class="cfg-section">
    <summary>定时与探测</summary>
    <div class="cfg-body">
      <div class="field-grid">
        <label>轮询周期（分钟）<input id="fSchedule" type="number" min="1"></label>
        <label>探测端口<input id="fPort" type="number" min="1" max="65535"></label>
        <label>并发数<input id="fConcurrency" type="number" min="1"></label>
        <label>最大候选 IP 数<input id="fMaxCandidates" type="number" min="1"></label>
        <label>TCP 探测轮数<input id="fTCPRounds" type="number" min="1"></label>
        <label>单次超时（秒）<input id="fTimeout" type="number" min="1"></label>
      </div>
    </div>
  </details>
  <details class="cfg-section">
    <summary>DNS 与切换策略</summary>
    <div class="cfg-body">
      <div class="field-grid">
        <label class="wide">探测 DNS（逗号分隔）<input id="fProbeDNS" type="text" placeholder="223.5.5.5, tls://dns.alidns.com, https://dns.cloudflare.com/dns-query"></label>
        <label>滞回百分比（%）<input id="fHystPct" type="number" min="0"></label>
        <label>滞回轮数<input id="fHystRounds" type="number" min="1"></label>
      </div>
      <p class="hint" style="margin:8px 0 0">支持 UDP（字面 IP）、DoT（tls://主机[:853]）、DoH（https://主机/路径），可混用；DoQ 暂不支持。</p>
    </div>
  </details>
  <details class="cfg-section">
    <summary>子域名展开</summary>
    <div class="cfg-body">
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
    </div>
  </details>
  <details class="cfg-section">
    <summary>域名列表</summary>
    <div class="cfg-body">
      <div id="domainEditor" class="domain-editor"></div>
      <div class="bar" style="margin-top:10px">
        <input id="newDomainName" type="text" placeholder="新增域名，如 example.com" spellcheck="false">
        <button id="addDomainBtn" type="button">添加域名</button>
      </div>
    </div>
  </details>
  <details class="cfg-section">
    <summary>历史记录</summary>
    <div class="cfg-body">
      <div class="field-grid">
        <label>历史保留（月）<input id="fHistoryRetention" type="number" min="1" max="120"></label>
      </div>
      <p class="hint" style="margin:8px 0 0">探测历史按月压缩存于状态目录的 history/ 下，超出保留期的分片会自动清理。</p>
    </div>
  </details>
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
<details id="domainListDetails">
<summary>域名列表 <span class="summary-meta">有效 {{.ActiveCount}}/{{.DomainCount}}</span></summary>
<div class="table-tools">
  <div class="left">
    <span id="selCount">已选 0 个域名</span>
    <button id="batchDelete" type="button" class="danger" disabled>删除选中</button>
    <button id="expandAll" type="button">全部展开</button>
    <button id="collapseAll" type="button">全部收起</button>
    <button id="batchRefresh" type="button" disabled>刷新选中</button>
  </div>
  <span class="hint" style="margin:0">按主域名分组；点分组标题展开该分类，勾选后可批量刷新或删除</span>
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
<tr data-name="{{$d.Name}}" data-ip="{{$d.IP}}" data-reason="{{$d.Reason}}" data-status="{{$d.Validated}}" data-pending="{{$d.Pending}}" data-disabled="{{$d.Disabled}}">
  <td class="select-cell"><input type="checkbox" class="row-check" value="{{$d.Name}}"></td>
  <td class="truncate" title="{{$d.Name}}">{{$d.Name}}</td>
  <td class="truncate" title="{{$d.IP}}">{{$d.IP}}</td>
  <td>{{if $d.IP}}<button type="button" class="latency-btn" data-domain="{{$d.Name}}" title="查看全部候选 IP">{{$d.LatencyMS}} ms</button>{{else}}—{{end}}</td>
  <td>
    {{if $d.Disabled}}
    <span class="status-dot status-unknown"></span>
    已禁用
    {{else if $d.Pending}}
    <span class="status-dot status-unknown"></span>
    待探测
    {{else}}
    <span class="status-dot {{if $d.Validated}}status-ok{{else}}status-fail{{end}}"></span>
    {{if $d.Validated}}正常{{else}}失败{{end}}
    {{end}}
  </td>
  <td>{{$d.Candidates}}/{{$d.Validated}}</td>
  <td>
    <button type="button" class="expand-btn" data-domain="{{$d.Name}}">展开域名</button>
    <button type="button" class="refresh-btn" data-domain="{{$d.Name}}" title="单独刷新该域名">刷新</button>
    <button type="button" class="disable-btn" data-domain="{{$d.Name}}" data-disabled="{{$d.Disabled}}">{{if $d.Disabled}}启用{{else}}禁用{{end}}</button>
    <span class="badge">{{$d.Reason}}</span>
  </td>
</tr>
{{end}}
</tbody></table>

</details>
</div>

<div class="card">
<details id="historyDetails">
<summary>历史趋势</summary>
<div class="history-tools">
  <select id="historyDomain"></select>
  <select id="historyRange">
    <option value="1">近 24 小时</option>
    <option value="7" selected>近 7 天</option>
    <option value="30">近 30 天</option>
    <option value="90">近 90 天</option>
  </select>
  <button id="historyRefresh" type="button">刷新</button>
  <span id="historyState"></span>
</div>
<div class="trend-wrap"><svg id="trendChart" viewBox="0 0 720 220" role="img" aria-label="平均延迟趋势"></svg></div>
<div class="history-table-wrap">
  <table class="history-table">
    <thead><tr><th>时间</th><th>域名</th><th>优选 IP</th><th>延迟</th><th>状态</th></tr></thead>
    <tbody id="historyRows"></tbody>
  </table>
</div>
</details>
</div>

<div class="card">
<details id="logDetails">
<summary>运行日志</summary>
<div class="log-tools">
  <label><input type="checkbox" id="logAuto" checked> 自动刷新</label>
  <input id="logFilter" type="text" placeholder="筛选关键字...">
  <button id="logClear" type="button">清空视图</button>
  <span id="logState"></span>
</div>
<pre id="logView"></pre>
</details>
</div>

<div class="card">
<details id="aboutDetails">
<summary>关于</summary>
<div class="about-grid">
  <div class="about-item"><span class="about-label">版本</span><span class="about-value mono">v{{.Version}}</span></div>
  <div class="about-item"><span class="about-label">项目地址</span><a class="about-value" href="{{.ProjectURL}}" target="_blank" rel="noopener">{{.ProjectURL}}</a></div>
</div>
<div class="about-block">
  <h4>使用说明</h4>
  <ol class="about-steps">
    <li>在「编辑域名清单」中添加域名，或输入主域名后勾选相关子域名批量添加，最后点「保存并生效」。</li>
    <li>在 AdGuard Home 打开「过滤器 → DNS 重写清单」，添加订阅地址 <code>http://&lt;NAS内网IP&gt;:18088/agh.txt</code>，更新间隔设为 1 小时。</li>
    <li>需要立即更新时，展开域名分组后勾选并点「刷新选中」；只想重写订阅文件时点「刷新 AGH 规则」。</li>
    <li>点击延迟数值可查看全部候选 IP 并手动切换；状态表支持按主域名分组以及启用/禁用域名。</li>
    <li>其他端点：<code>/hosts.txt</code>（hosts 语法）、<code>/status.json</code>（运行状态与统计）。</li>
  </ol>
</div>
<div class="about-foot">管理接口无登录鉴权，请仅在内网使用；刷新任务状态保存在进程内存，重启后重新触发即可。</div>
</details>
</div>

<div class="modal-overlay" id="expandModal">
  <div class="modal">
    <h3>展开域名: <span id="modalDomain" style="font-family:var(--mono);color:var(--accent)"></span></h3>
    <div class="progress"><div class="progress-bar" id="progressBar"></div></div>
    <p id="progressText" class="modal-hint">准备中...</p>
    <div class="result-list" id="resultList"></div>
    <div class="modal-actions">
      <button type="button" id="modalClose">关闭</button>
      <button type="button" id="modalAddAll" class="primary" disabled>全部添加到配置</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="ipModal">
  <div class="modal">
    <h3>候选 IP 延时: <span id="ipDomain" style="font-family:var(--mono);color:var(--accent)"></span></h3>
    <p class="hint" id="ipHint"></p>
    <div class="result-list" id="ipList"></div>
    <div class="modal-actions">
      <button type="button" id="ipClose">关闭</button>
    </div>
  </div>
</div>

<script>
(function () {
  var inp = document.getElementById("sub");
  var msg = document.getElementById("msg");
  var themeSel = document.getElementById("themeSel");
  var scheme = window.matchMedia("(prefers-color-scheme: dark)");
  function currentTheme() {
    try { return localStorage.getItem("ho-theme") || "system"; } catch (e) { return "system"; }
  }
  function applyTheme(mode) {
    var dark = mode === "dark" || (mode === "system" && scheme.matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    themeSel.value = mode;
  }
  applyTheme(currentTheme());
  themeSel.onchange = function () {
    try { localStorage.setItem("ho-theme", themeSel.value); } catch (e) {}
    applyTheme(themeSel.value);
  };
  var onSchemeChange = function () {
    if (currentTheme() === "system") applyTheme("system");
  };
  if (scheme.addEventListener) scheme.addEventListener("change", onSchemeChange);
  else if (scheme.addListener) scheme.addListener(onSchemeChange);

  inp.value = location.origin + "/agh.txt";
  document.getElementById("copy").onclick = function () {
    inp.select();
    try { document.execCommand("copy"); msg.textContent = "已复制"; }
    catch (e) { msg.textContent = "请手动复制上方的地址"; }
  };
  var btn = document.getElementById("refresh");
  // 刷新改为后台任务：POST 拿到 task_id 后轮询状态，避免长请求卡住页面。
  function startRefresh(statusEl, done, domains, retried) {
    statusEl.textContent = "正在轮询，请稍等";
    var opts = { method: "POST" };
    if (domains && domains.length) {
      opts.headers = { "Content-Type": "application/json" };
      opts.body = JSON.stringify({ domains: domains });
    }
    fetch("/refresh", opts)
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (x) {
        if (!x.body.ok || !x.body.task_id) {
          throw new Error(x.body.error || ("HTTP " + x.status));
        }
        var reused = !!x.body.reused;
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
                if (reused && !retried) {
                  statusEl.textContent = "上一任务已完成，正在按最新配置重新探测...";
                  startRefresh(statusEl, done, domains, true);
                  return;
                }
                statusEl.textContent = "完成，AGH 订阅已同步，即将刷新页面";
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
    msg.textContent = "正在刷新 AGH 规则...";
    fetch("/api/refresh-agh", { method: "POST" })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (x) {
        btn.disabled = false;
        if (x.body.ok) {
          msg.textContent = "AGH 规则已刷新（" + x.body.bytes + " 字节）";
        } else {
          msg.textContent = "刷新失败: " + (x.body.error || ("HTTP " + x.status));
        }
      })
      .catch(function (e) {
        btn.disabled = false;
        msg.textContent = "请求失败: " + e;
      });
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

    var disabledLabel = document.createElement("label");
    var disabled = document.createElement("input");
    disabled.type = "checkbox";
    disabled.className = "d-disabled";
    disabled.checked = !!d.disabled;
    disabledLabel.appendChild(disabled);
    disabledLabel.appendChild(document.createTextNode(" 禁用"));

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
    main.appendChild(disabledLabel);
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
    numTo(document.getElementById("fHistoryRetention"), d.history_retention_months, 12);
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
    setNum(d, "history_retention_months", document.getElementById("fHistoryRetention"), 12);
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
      if (item.querySelector(".d-disabled").checked) {
        base.disabled = true;
      } else {
        delete base.disabled;
      }
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
        cfgMsg.textContent = "已保存，正在刷新列表...";
        setTimeout(function () { location.reload(); }, 400);
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

  // 分组展开状态只由用户手动操作写入；禁用/切换/刷新导致页面重载时据此恢复，
  // 绝不因为一次禁用或勾选就自动收起所有分组。
  function readGroupOpenState() {
    try { return JSON.parse(localStorage.getItem("ho-group-open") || "{}"); }
    catch (e) { return {}; }
  }
  function writeGroupOpenState(state) {
    try { localStorage.setItem("ho-group-open", JSON.stringify(state)); } catch (e) {}
  }
  function setGroupOpen(g, open, persist) {
    g.open = open;
    g.head.classList.toggle("open", open);
    g.caret.textContent = open ? "▼" : "▶";
    if (persist) {
      var state = readGroupOpenState();
      state[g.base] = open;
      writeGroupOpenState(state);
    }
  }

  function baseDomain(name) {
    var parts = String(name || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    var lastTwo = parts.slice(-2).join(".");
    if (multiSuffix[lastTwo]) return parts.slice(-3).join(".");
    return lastTwo;
  }

  function buildGroups() {
    var map = {};
    var savedOpen = readGroupOpenState();
    rows.forEach(function (tr) {
      var base = baseDomain(tr.dataset.name);
      if (!map[base]) {
        map[base] = { base: base, rows: [], open: !!savedOpen[base], visible: [] };
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
      caret.textContent = g.open ? "▼" : "▶";
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

      var disableLabel = document.createElement("label");
      disableLabel.className = "group-select";
      var groupDisable = document.createElement("input");
      groupDisable.type = "checkbox";
      disableLabel.appendChild(groupDisable);
      disableLabel.appendChild(document.createTextNode(" 禁用本组"));

      wrap.appendChild(toggle);
      wrap.appendChild(selectLabel);
      wrap.appendChild(disableLabel);
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
      g.disableCheck = groupDisable;

      toggle.onclick = function () {
        setGroupOpen(g, !g.open, true);
        applyFilter();
      };
      head.classList.toggle("open", g.open);
      groupCheck.onchange = function () {
        g.visible.forEach(function (tr) {
          var c = tr.querySelector(".row-check");
          if (c) c.checked = groupCheck.checked;
        });
        updateSelection();
      };
      groupDisable.onchange = function () {
        var names = g.rows.map(function (tr) { return tr.dataset.name; });
        if (names.length === 0) return;
        var wantDisabled = groupDisable.checked;
        groupDisable.disabled = true;
        applyDisable(names, wantDisabled, function (ok) {
          groupDisable.disabled = false;
          if (ok) {
            msg.textContent = (wantDisabled ? "已禁用 " : "已启用 ") + names.length + " 个域名";
            setTimeout(function () { location.reload(); }, 600);
          } else {
            groupDisable.checked = !wantDisabled;
          }
        });
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
        var pending = tr.dataset.pending === "true";
        var disabled = tr.dataset.disabled === "true";
        var match = !kw || name.indexOf(kw) >= 0 || ip.indexOf(kw) >= 0 || reason.indexOf(kw) >= 0;
        var statusMatch = st === "all" || (st === "ok" && validated) ||
          (st === "fail" && !validated && !pending && !disabled) ||
          (st === "pending" && pending && !disabled) ||
          (st === "disabled" && disabled);
        return match && statusMatch;
      });
      g.visible = visible;
      filteredRows = filteredRows.concat(visible);
      g.head.classList.toggle("table-row-hidden", visible.length === 0);
      // 搜索命中时临时展开以露出结果，但不写入持久状态：清空关键词后
      // 仍按用户上次的手动选择显示，避免搜索意外改变分组开合。
      if (kw && visible.length > 0 && !g.open) {
        g.open = true;
        g.head.classList.add("open");
        g.caret.textContent = "▼";
        g.autoOpened = true;
      } else if (!kw && g.autoOpened) {
        g.open = false;
        g.head.classList.remove("open");
        g.caret.textContent = "▶";
        g.autoOpened = false;
      }
      g.rows.forEach(function (tr) {
        tr.classList.toggle("table-row-hidden", !g.open || visible.indexOf(tr) < 0);
      });
      var okCount = visible.filter(function (tr) { return tr.dataset.status === "true"; }).length;
      g.count.textContent = visible.length + " 个域名";
      g.ok.textContent = okCount + " 正常";
      g.ok.className = "group-ok" + (visible.length - okCount > 0 ? " has-bad" : "");
      if (g.disableCheck) {
        var allDisabled = visible.length > 0 && visible.every(function (tr) {
          return tr.dataset.disabled === "true";
        });
        g.disableCheck.checked = allDisabled;
        g.disableCheck.indeterminate = !allDisabled && visible.some(function (tr) {
          return tr.dataset.disabled === "true";
        });
      }
    });
    updateSelection();
  }

  searchInput.addEventListener("input", applyFilter);
  statusFilter.addEventListener("change", applyFilter);

  // 启用/禁用域名（立即写回配置并从产物移除）
  function applyDisable(names, disabled, done) {
    fetch("/api/disable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ names: names, disabled: disabled })
    }).then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }); })
      .then(function (x) {
        if (!x.body.ok) {
          msg.textContent = "操作失败: " + (x.body.error || ("HTTP " + x.status));
          if (done) done(false);
          return;
        }
        if (done) done(true);
      })
      .catch(function (e) {
        msg.textContent = "请求失败: " + e;
        if (done) done(false);
      });
  }
  document.querySelectorAll(".disable-btn").forEach(function (btn) {
    btn.onclick = function () {
      var name = btn.dataset.domain;
      var wantDisabled = btn.dataset.disabled !== "true";
      btn.disabled = true;
      applyDisable([name], wantDisabled, function (ok) {
        btn.disabled = false;
        if (ok) {
          msg.textContent = (wantDisabled ? "已禁用 " : "已启用 ") + name;
          setTimeout(function () { location.reload(); }, 600);
        }
      });
    };
  });

  // 表格勾选与批量删除
  var selectAll = document.getElementById("selectAll");
  var selCount = document.getElementById("selCount");
  var batchDelete = document.getElementById("batchDelete");
  var expandAllBtn = document.getElementById("expandAll");
  var collapseAllBtn = document.getElementById("collapseAll");
  var batchRefresh = document.getElementById("batchRefresh");

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
    batchRefresh.disabled = total === 0;
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
      setGroupOpen(g, true, true);
    });
    applyFilter();
  };
  collapseAllBtn.onclick = function () {
    groups.forEach(function (g) {
      setGroupOpen(g, false, true);
    });
    applyFilter();
  };
  batchRefresh.onclick = function () {
    var names = selectedNames();
    if (names.length === 0) return;
    batchRefresh.disabled = true;
    batchRefresh.textContent = "刷新中...";
    msg.textContent = "正在刷新选中的 " + names.length + " 个域名...";
    startRefresh(msg, function () {
      batchRefresh.disabled = false;
      batchRefresh.textContent = "刷新选中";
    }, names);
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
      progressBar.style.background = "";
      progressText.textContent = "正在查询子域名...";
      resultList.innerHTML = "";
      modalAddAll.disabled = true;
      modal.classList.add("show");
      doExpand(domain);
    };
  });

  function doExpand(domain) {
    progressBar.style.width = "0%";
    progressBar.style.background = "";
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
          renderEmpty("查询失败，请稍后重试", true);
          return;
        }
        expandResults = j.results || [];
        renderResults();
        progressBar.style.width = "100%";
        progressText.textContent = "完成: 共 " + expandResults.length + " 个子域名，" + expandResults.filter(function(r){return r.resolved}).length + " 个可解析";
        modalAddAll.disabled = expandResults.length === 0;
      })
      .catch(function(e) {
        progressText.textContent = "请求失败: " + e.message;
        progressBar.style.width = "100%";
        progressBar.style.background = "#f44336";
        renderEmpty("网络请求失败，请检查连接后重试", true);
      });
  }

  function renderEmpty(text, retry) {
    resultList.innerHTML = "";
    var box = document.createElement("div");
    box.className = "modal-empty";
    var tip = document.createElement("div");
    tip.textContent = text;
    box.appendChild(tip);
    if (retry) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = "重试";
      btn.onclick = function () {
        progressText.textContent = "正在重新查询子域名...";
        resultList.innerHTML = "";
        doExpand(modalDomain.textContent);
      };
      box.appendChild(btn);
    }
    resultList.appendChild(box);
  }

  function renderResults() {
    resultList.innerHTML = "";
    if (expandResults.length === 0) {
      renderEmpty("未发现相关子域名，可稍后重试或更换主域名", false);
      return;
    }
    expandResults.forEach(function(r) {
      var item = document.createElement("div");
      item.className = "result-item " + (r.resolved ? "result-ok" : "result-fail");
      var dot = document.createElement("span");
      dot.className = "result-dot";
      var main = document.createElement("div");
      main.className = "result-main";
      var line = document.createElement("div");
      line.className = "result-line";
      var domain = document.createElement("span");
      domain.className = "result-domain";
      domain.textContent = r.domain;
      var source = document.createElement("span");
      source.className = "result-source " + sourceClass(r.source);
      source.textContent = sourceLabel(r.source);
      line.appendChild(domain);
      line.appendChild(source);
      var ips = document.createElement("div");
      ips.className = "result-ips";
      ips.textContent = (r.ips && r.ips.length) ? r.ips.join("  ") : "不可解析";
      main.appendChild(line);
      main.appendChild(ips);
      item.appendChild(dot);
      item.appendChild(main);
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

  // 候选 IP 延时与手动切换
  var ipModal = document.getElementById("ipModal");
  var ipDomain = document.getElementById("ipDomain");
  var ipHint = document.getElementById("ipHint");
  var ipList = document.getElementById("ipList");
  document.getElementById("ipClose").onclick = function () { ipModal.classList.remove("show"); };
  ipModal.onclick = function (e) { if (e.target === ipModal) ipModal.classList.remove("show"); };

  function switchIP(domain, ip) {
    ipHint.textContent = "正在切换到 " + ip + "...";
    fetch("/api/switch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: domain, ip: ip })
    }).then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) {
          ipHint.textContent = "切换失败: " + (j.error || "未知错误");
          return;
        }
        ipHint.textContent = "已切换到 " + ip + "，AGH 订阅已同步，即将刷新页面";
        setTimeout(function () { location.reload(); }, 700);
      })
      .catch(function (e) { ipHint.textContent = "请求失败: " + e; });
  }

  function openCandidates(domain) {
    ipDomain.textContent = domain;
    ipHint.textContent = "加载中...";
    ipList.innerHTML = "";
    ipModal.classList.add("show");
    fetch("/api/candidates?domain=" + encodeURIComponent(domain))
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) {
          ipHint.textContent = "加载失败: " + (j.error || "未知错误");
          return;
        }
        var list = j.candidates || [];
        ipHint.textContent = "共 " + list.length + " 个可连接 IP，当前生效 " + (j.current_ip || "无");
        if (list.length === 0) {
          var empty = document.createElement("div");
          empty.className = "dropdown-empty";
          empty.textContent = "本轮没有可连接的 IP";
          ipList.appendChild(empty);
          return;
        }
        list.forEach(function (c) {
          var item = document.createElement("div");
          item.className = "result-item result-ok";
          var dot = document.createElement("span");
          dot.className = "result-dot";
          var info = document.createElement("div");
          info.className = "result-info";
          var ipEl = document.createElement("div");
          ipEl.className = "result-domain";
          ipEl.textContent = c.ip;
          info.appendChild(ipEl);
          item.appendChild(dot);
          item.appendChild(info);
          var meta = document.createElement("span");
          meta.className = "result-ips";
          meta.textContent = (Math.round(c.latency_ms * 10) / 10) + " ms";
          item.appendChild(meta);
          if (c.ip === j.current_ip) {
            var badge = document.createElement("span");
            badge.className = "badge";
            badge.textContent = "当前";
            item.appendChild(badge);
          } else {
            var sw = document.createElement("button");
            sw.type = "button";
            sw.className = "switch-btn";
            sw.textContent = "切换";
            sw.onclick = function () { switchIP(domain, c.ip); };
            item.appendChild(sw);
          }
          ipList.appendChild(item);
        });
      })
      .catch(function (e) { ipHint.textContent = "请求失败: " + e; });
  }
  document.querySelectorAll(".latency-btn").forEach(function (el) {
    el.onclick = function () { openCandidates(el.dataset.domain); };
  });

  // 单独刷新域名（实际触发一轮全量探测，按钮仅作快捷入口）
  document.querySelectorAll(".refresh-btn").forEach(function(rowBtn) {
    rowBtn.onclick = function() {
      var domain = rowBtn.dataset.domain;
      rowBtn.disabled = true;
      rowBtn.textContent = "刷新中...";
      msg.textContent = "正在刷新 " + domain + "...";
      startRefresh(msg, function() {
        rowBtn.disabled = false;
        rowBtn.textContent = "刷新";
      }, [domain]);
    };
  });

  // 历史趋势：近 N 天平均延迟 + 最近记录
  var historyDetails = document.getElementById("historyDetails");
  var historyDomain = document.getElementById("historyDomain");
  var historyRange = document.getElementById("historyRange");
  var historyRefresh = document.getElementById("historyRefresh");
  var historyState = document.getElementById("historyState");
  var historyRows = document.getElementById("historyRows");
  var trendChart = document.getElementById("trendChart");
  var SVGNS = "http://www.w3.org/2000/svg";

  function initHistoryDomains() {
    var seen = {};
    var names = [];
    rows.forEach(function (tr) {
      var n = tr.dataset.name;
      if (n && !seen[n]) { seen[n] = true; names.push(n); }
    });
    names.sort();
    var all = document.createElement("option");
    all.value = "";
    all.textContent = "全部域名";
    historyDomain.appendChild(all);
    names.forEach(function (n) {
      var opt = document.createElement("option");
      opt.value = n;
      opt.textContent = n;
      historyDomain.appendChild(opt);
    });
  }

  function fmtLocal(iso, withDate) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    function p(n) { return n < 10 ? "0" + n : "" + n; }
    var time = p(d.getHours()) + ":" + p(d.getMinutes());
    return withDate ? (d.getMonth() + 1) + "-" + p(d.getDate()) + " " + time : time;
  }

  function svgEl(tag, attrs) {
    var el = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }

  function renderTrend(records, days) {
    trendChart.textContent = "";
    var W = 720, H = 220, L = 46, R = 14, T = 16, B = 28;
    var now = new Date();
    var from = new Date(now.getTime() - days * 86400000);
    var sizeMs = days <= 1 ? 3600000 : (days <= 7 ? 6 * 3600000 : (days <= 30 ? 86400000 : 3 * 86400000));
    var bucketCount = Math.max(1, Math.ceil((now - from) / sizeMs));
    var sums = new Array(bucketCount).fill(0);
    var counts = new Array(bucketCount).fill(0);
    records.forEach(function (r) {
      if (!r.validated || !r.latency_ms) return;
      var t = new Date(r.time).getTime();
      if (isNaN(t) || t < from.getTime() || t > now.getTime()) return;
      var idx = Math.floor((t - from.getTime()) / sizeMs);
      if (idx < 0) idx = 0;
      if (idx >= bucketCount) idx = bucketCount - 1;
      sums[idx] += r.latency_ms;
      counts[idx]++;
    });
    var avgs = [];
    var maxAvg = 0;
    for (var i = 0; i < bucketCount; i++) {
      var v = counts[i] ? sums[i] / counts[i] : null;
      avgs.push(v);
      if (v !== null && v > maxAvg) maxAvg = v;
    }
    var maxY = Math.max(10, Math.ceil(maxAvg * 1.2 / 10) * 10);

    var plotW = W - L - R, plotH = H - T - B;
    function x(i) { return L + (bucketCount === 1 ? plotW / 2 : (i / (bucketCount - 1)) * plotW); }
    function y(v) { return T + plotH - (v / maxY) * plotH; }

    for (var g = 0; g <= 3; g++) {
      var gv = maxY * g / 3;
      var gy = y(gv);
      trendChart.appendChild(svgEl("line", { x1: L, y1: gy, x2: W - R, y2: gy, class: "trend-grid" }));
      var label = svgEl("text", { x: L - 8, y: gy + 4, class: "trend-label", "text-anchor": "end" });
      label.textContent = Math.round(gv) + "ms";
      trendChart.appendChild(label);
    }

    var d = "", started = false;
    for (var j = 0; j < bucketCount; j++) {
      if (avgs[j] === null) { started = false; continue; }
      d += (started ? " L" : " M") + x(j).toFixed(1) + " " + y(avgs[j]).toFixed(1);
      started = true;
      trendChart.appendChild(svgEl("circle", { cx: x(j), cy: y(avgs[j]), r: 3, class: "trend-dot" }));
    }
    if (d) {
      trendChart.appendChild(svgEl("path", { d: d, class: "trend-line" }));
    } else {
      var empty = svgEl("text", { x: W / 2, y: H / 2, class: "trend-label", "text-anchor": "middle" });
      empty.textContent = "暂无历史数据";
      trendChart.appendChild(empty);
    }

    var ticks = 4;
    for (var k = 0; k < ticks; k++) {
      var ts = from.getTime() + (now.getTime() - from.getTime()) * (k / (ticks - 1));
      var td = new Date(ts);
      var lbl = svgEl("text", {
        x: L + (k / (ticks - 1)) * plotW, y: H - 8, class: "trend-label",
        "text-anchor": k === 0 ? "start" : (k === ticks - 1 ? "end" : "middle")
      });
      lbl.textContent = days <= 1 ? fmtLocal(td.toISOString(), false) : (td.getMonth() + 1) + "-" + td.getDate();
      trendChart.appendChild(lbl);
    }
  }

  function renderHistoryRows(records) {
    var list = records.slice(-100).reverse();
    historyRows.textContent = "";
    if (list.length === 0) {
      var tr = document.createElement("tr");
      var td = document.createElement("td");
      td.colSpan = 5;
      td.className = "history-empty";
      td.textContent = "暂无历史记录";
      tr.appendChild(td);
      historyRows.appendChild(tr);
      return;
    }
    list.forEach(function (r) {
      var tr = document.createElement("tr");
      var cells = [
        fmtLocal(r.time, true),
        r.domain,
        r.ip || "—",
        r.latency_ms ? Math.round(r.latency_ms * 10) / 10 + " ms" : "—"
      ];
      cells.forEach(function (text) {
        var td = document.createElement("td");
        td.textContent = text;
        tr.appendChild(td);
      });
      var st = document.createElement("td");
      var dot = document.createElement("span");
      dot.className = "status-dot " + (r.validated ? "status-ok" : "status-fail");
      st.appendChild(dot);
      st.appendChild(document.createTextNode(r.validated ? "正常" : "失败"));
      tr.appendChild(st);
      historyRows.appendChild(tr);
    });
  }

  function fetchHistory() {
    var days = parseInt(historyRange.value, 10) || 7;
    var now = new Date();
    var from = new Date(now.getTime() - days * 86400000);
    var url = "/api/history?from=" + encodeURIComponent(from.toISOString()) +
      "&to=" + encodeURIComponent(now.toISOString()) + "&limit=5000";
    if (historyDomain.value) url += "&domain=" + encodeURIComponent(historyDomain.value);
    historyState.textContent = "加载中...";
    fetch(url)
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) {
          historyState.textContent = "加载失败: " + (j.error || "未知错误");
          return;
        }
        var records = j.records || [];
        renderTrend(records, days);
        renderHistoryRows(records);
        historyState.textContent = "共 " + records.length + " 条记录";
      })
      .catch(function (e) { historyState.textContent = "加载失败: " + e; });
  }

  initHistoryDomains();
  historyRefresh.onclick = fetchHistory;
  historyRange.onchange = fetchHistory;
  historyDomain.onchange = fetchHistory;
  historyDetails.addEventListener("toggle", function () {
    if (historyDetails.open) fetchHistory();
  });

  // 运行日志：增量拉取 + 关键字筛选
  var logView = document.getElementById("logView");
  var logAuto = document.getElementById("logAuto");
  var logFilter = document.getElementById("logFilter");
  var logClear = document.getElementById("logClear");
  var logState = document.getElementById("logState");
  var logDetails = document.getElementById("logDetails");
  var logEntries = [];
  var logSeq = 0;

  function renderLogs() {
    var kw = logFilter.value.trim().toLowerCase();
    var rows = logEntries.filter(function (e) {
      return !kw || String(e.text || "").toLowerCase().indexOf(kw) >= 0;
    });
    var atBottom = logView.scrollTop + logView.clientHeight >= logView.scrollHeight - 24;
    logView.textContent = "";
    rows.forEach(function (e) {
      var line = document.createElement("span");
      line.className = "log-line";
      line.appendChild(document.createTextNode(e.text || ""));
      logView.appendChild(line);
    });
    if (atBottom) logView.scrollTop = logView.scrollHeight;
    logState.textContent = rows.length + " 条" + (kw ? "（已筛选）" : "") + " · 最新序号 " + logSeq;
  }
  function fetchLogs() {
    fetch("/api/logs?after=" + logSeq + "&limit=500")
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j.ok) return;
        if (j.entries && j.entries.length) {
          logEntries = logEntries.concat(j.entries);
          if (logEntries.length > 2000) logEntries = logEntries.slice(logEntries.length - 2000);
        }
        logSeq = j.last_seq || logSeq;
        renderLogs();
      })
      .catch(function () {});
  }
  logFilter.addEventListener("input", renderLogs);
  logClear.onclick = function () { logEntries = []; renderLogs(); };
  logAuto.onchange = function () { if (logAuto.checked) fetchLogs(); };
  logDetails.addEventListener("toggle", function () { if (logDetails.open) fetchLogs(); });
  fetchLogs();
  setInterval(function () {
    if (logAuto.checked && logDetails.open) fetchLogs();
  }, 2500);
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
	views := buildDomainViews(snap.Status.Domains)
	active := 0
	for _, v := range views {
		if v.Validated > 0 && !v.Disabled {
			active++
		}
	}
	data := struct {
		GeneratedAt     string
		ScheduleMinutes int
		ActiveCount     int
		DomainCount     int
		Ready           bool
		Domains         []domainView
		Version         string
		ProjectURL      string
	}{
		GeneratedAt:     snap.Status.GeneratedAt.Format(time.RFC3339),
		ScheduleMinutes: snap.Status.ScheduleMinutes,
		ActiveCount:     active,
		DomainCount:     len(views),
		Ready:           active > 0,
		Domains:         views,
		Version:         a.version,
		ProjectURL:      "https://github.com/wulinwei959/ip-optimizer",
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTmpl.Execute(w, data); err != nil {
		log.Printf("渲染首页失败: %v", err)
	}
}

// domainView 是首页表格的一行：快照状态 + 配置里的启用/待探测标记。
type domainView struct {
	Name       string
	IP         string
	LatencyMS  float64
	Reason     string
	Validated  int
	Candidates int
	Disabled   bool
	Pending    bool
}

// buildDomainViews 合并「配置中的域名」与「本轮快照」，未探测的标记待探测，
// 配置里禁用的标记已禁用。
func buildDomainViews(snapDomains []output.StatusDomain) []domainView {
	var cfgDomains []config.Domain
	if rt, err := config.Load(); err == nil {
		cfgDomains = rt.Config.Domains
	}
	return mergeDomainViews(snapDomains, cfgDomains)
}

// mergeDomainViews 是 buildDomainViews 的纯函数版本，便于测试。
func mergeDomainViews(snapDomains []output.StatusDomain, cfgDomains []config.Domain) []domainView {
	disabled := make(map[string]bool, len(cfgDomains))
	names := make([]string, 0, len(cfgDomains))
	for _, d := range cfgDomains {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
		if d.Disabled {
			disabled[name] = true
		}
	}
	out := make([]domainView, 0, len(snapDomains)+len(names))
	seen := make(map[string]bool, len(snapDomains)+len(names))
	for _, d := range snapDomains {
		seen[d.Name] = true
		v := domainView{
			Name: d.Name, IP: d.IP, LatencyMS: d.LatencyMS, Reason: d.Reason,
			Validated: d.Validated, Candidates: d.Candidates, Disabled: disabled[d.Name],
		}
		if v.Disabled {
			v.Reason = "已禁用"
		}
		out = append(out, v)
	}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		v := domainView{Name: name, Disabled: disabled[name], Pending: true, Reason: "待探测"}
		if v.Disabled {
			v.Reason = "已禁用"
		}
		out = append(out, v)
	}
	return out
}
