// Package app 编排一轮探测、进程内定时、单端口 HTTP 服务与产物落盘。
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"sync/atomic"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/dnsquery"
	"hosts-optimizer/internal/dnsserver"
	"hosts-optimizer/internal/expand"
	"hosts-optimizer/internal/history"
	"hosts-optimizer/internal/logbuf"
	"hosts-optimizer/internal/output"
	"hosts-optimizer/internal/probe"
	"hosts-optimizer/internal/store"
	"hosts-optimizer/internal/ui"
	"hosts-optimizer/internal/update"
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
	// adminToken 是管理端点的访问令牌；为空表示未启用鉴权。
	adminToken string
	dataDir    string

	// updateChecker 周期性检查 GitHub 新版本（HO_UPDATE_CHECK=off 可关）。
	updateChecker *update.Checker

	// 手动检查更新的限流状态：60 秒内重复触发返回 429。
	updateCheckMu   sync.Mutex
	lastUpdateCheck time.Time

	// 健康探针退避：记录每个域名上次触发即时轮次的时间与退避间隔。
	watchMu            sync.Mutex
	watchStates        map[string]watchState
	watchLastCheck     time.Time
	watchLastDegraded  []string
	watchLastTriggered []string

	mu           sync.RWMutex
	snap         *output.Snapshot
	// roundMu 是带超时获取能力的轮次锁（channel 令牌实现），见 roundlock.go。
	// 各入口按自身性质用 tryLockTimeout 限时等待：周期任务拿不到即跳过，
	// 用户显式操作拿不到即返回 409，都不允许无限排队。
	roundMu     *timedMutex
	lastSchedule int

	// DNS 应答器（AdGuard Home 上游分流模式）
	dnsSrv    *dnsserver.Server // listen 为空时为 nil（禁用）
	dnsListen string
	dnsMu     sync.RWMutex // 保护 dnsSrv / dnsListen 的换绑
	dnsTTL    atomic.Int64
	startedAt time.Time
	roundSeq  atomic.Int64 // 原子计数器，生成唯一 RoundID
	// dnsFamilies 保存「启用域名的完整名」指针，生成 AGH 上游分流行用。
	// 定时轮次与 HTTP 请求会并发读写该字段，因此存指针并原子替换：
	// 直接存切片会造成 slice 头（ptr/len/cap）的撕裂读，输出半新半旧的域名清单。
	dnsFamilies atomic.Pointer[[]string]

	// 异步刷新任务
	refreshMu   sync.Mutex
	refreshTask *refreshTask
	lastRefresh time.Time // 上次手动刷新启动时间，用于限流

	// 子域扩展结果缓存：定时轮次复用 TTL 内的展开结果，避免每轮都重新发现子域名。
	// 键为主域名名；entry 保存已解析的子域名结果，构建 targets 时仍从当轮 t 取基础参数，
	// 避免缓存命中时沿用过期的 SNI/端口等配置。
	expandCacheMu sync.Mutex
	expandCache   map[string]expandCacheEntry
	expandHits    atomic.Uint64
	expandMisses  atomic.Uint64
	expandCacheSize atomic.Int64 // 当前缓存条目数，/healthz 观测有界化是否生效

	// 长期运行观测（/healthz）：轮次耗时、超时/失败计数、锁排队计数、各缓存规模。
	roundDurationMs   atomic.Int64
	roundTimeoutCount atomic.Uint64
	roundLastStatus   atomic.Value // string: ok / timeout / error
	lockBusyCount     atomic.Uint64
	watchStatesSize   atomic.Int64
	stateDomainsSize  atomic.Int64

	// DNS 应答器生命周期：监听地址变更时需要重绑，故保存根 ctx 与取消函数。
	dnsBaseCtx context.Context
	dnsCancel  context.CancelFunc
	dnsDone    chan struct{}
	errCh      chan error
}

// 刷新任务状态取值。
const (
	refreshRunning = "running"
	refreshDone    = "done"
	refreshFailed  = "error"
)

// refreshMinInterval 是手动刷新的最小间隔，防止连续点击造成探测风暴。
// 已有任务在跑时直接复用，不受此限制；watchdog 走 doRoundFor 不经过此限流。
const refreshMinInterval = 10 * time.Second

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

// expandCacheEntry 缓存一次域名展开的已解析子域名结果。
// fingerprint 记录影响展开结果的参数，任一变化都会让该条缓存失效。
type expandCacheEntry struct {
	fingerprint string
	results     []expand.Result
	savedAt     time.Time
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
		port:          rt.Port,
		configPath:    filepath.Join(rt.ConfigDir, "domains.json"),
		hostsPath:     filepath.Join(rt.OutputDir, "hosts.txt"),
		aghPath:       filepath.Join(rt.OutputDir, "agh.txt"),
		statusPath:    filepath.Join(rt.OutputDir, "status.json"),
		statePath:     filepath.Join(rt.StateDir, "state.json"),
		rootCAs:       pool,
		state:         st,
		history:       hs,
		version:       version,
		adminToken:    resolveAdminToken(rt.DataDir),
		dataDir:       rt.DataDir,
		watchStates:   map[string]watchState{},
		lastSchedule:  rt.Config.Defaults.ScheduleMinutes,
		startedAt:     time.Now(),
		updateChecker: update.New(version),
		roundMu:       newTimedMutex(),
	}
	// 必须先于 recoverSnapshot：恢复流程会刷新应答视图。
	a.initDNSServer(rt)
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

// resolveAdminToken 决定管理端点的访问令牌。
//
// 服务默认监听所有网卡（订阅端要被 AGH/局域网访问），但 /api/* 与 /refresh
// 能改写配置、触发探测、手动换 IP —— 局域网里任何人都能干这些事。
// 优先级：HO_ADMIN_TOKEN 环境变量 > 数据目录 admin-token 文件 > 新生成。
// 生成的令牌持久化到数据目录（FPK 下是用户可见的共享文件夹），重启后复用，
// 用户可在文件管理器里直接查看；无数据目录时退化为每次启动随机生成并打印一次。
func resolveAdminToken(dataDir string) string {
	if v := strings.TrimSpace(os.Getenv("HO_ADMIN_TOKEN")); v != "" {
		return v
	}
	tokenPath := ""
	if dataDir != "" {
		tokenPath = filepath.Join(dataDir, "admin-token")
		if data, err := os.ReadFile(tokenPath); err == nil {
			if tok := strings.TrimSpace(string(data)); tok != "" {
				log.Printf("管理令牌已从 %s 加载（重启不变）", tokenPath)
				return tok
			}
		}
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		log.Printf("生成管理令牌失败，管理端点暂不校验: %v", err)
		return ""
	}
	tok := hex.EncodeToString(b)
	if tokenPath != "" {
		err := os.MkdirAll(dataDir, 0o755)
		if err == nil {
			err = os.WriteFile(tokenPath, []byte(tok+"\n"), 0o600)
		}
		if err != nil {
			log.Printf("管理令牌写入 %s 失败（本次仍可用，重启会重新生成）: %v", tokenPath, err)
		} else {
			log.Printf("管理令牌已生成并保存到 %s（文件管理器可见，重启不变）", tokenPath)
		}
	}
	log.Printf("管理令牌（仅本次启动打印一次）: %s", tok)
	return tok
}

// adminPaths 是需要管理令牌的端点。订阅端点与首页保持开放，
// 否则 AGH 拉不到订阅、用户连界面都进不去。
var adminPaths = map[string]bool{
	"/refresh":         true,
	"/api/domains":     true,
	"/api/expand":      true,
	"/api/logs":        true,
	"/api/history":     true,
	"/api/candidates":  true,
	"/api/switch":      true,
	"/api/refresh-agh": true,
	"/api/disable":     true,
	"/api/update-check": true,
}

// admin 给管理端点加一层令牌校验，供直接注册在 mux 上的路由复用。
func (a *App) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.checkAdmin(w, r) {
			return
		}
		h(w, r)
	}
}

// checkAdmin 校验令牌；token 为空表示未启用鉴权，直接放行。
// 令牌可放在 X-Admin-Token 头、Authorization: Bearer 或 ?token= 里。
func (a *App) checkAdmin(w http.ResponseWriter, r *http.Request) bool {
	if a.adminToken == "" {
		return true
	}
	given := r.Header.Get("X-Admin-Token")
	if given == "" {
		given = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if given == "" {
		given = r.URL.Query().Get("token")
	}
	if subtle.ConstantTimeCompare([]byte(given), []byte(a.adminToken)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"ok": false, "error": "需要管理令牌：请在界面填写，或用 X-Admin-Token 头 / ?token= 传入",
		})
		return false
	}
	return true
}

// recoverSnapshot 让服务重启后立刻能对外提供上一轮订阅内容，不必等首轮探测结束。
func (a *App) recoverSnapshot() {
	// 先恢复 status.json：即便 hosts.txt / agh.txt 缺失，应答器也能立即服务，
	// 否则重启后到首轮探测完成前，分流域名会全部 REFUSED，等于自己断网几十秒。
	if b, err := os.ReadFile(a.statusPath); err == nil {
		var st output.Status
		if json.Unmarshal(b, &st) == nil {
			a.applyDNSSnapshot(&output.Snapshot{Status: st})
		}
	}
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
	a.applyDNSSnapshot(snap)
	log.Printf("已从磁盘恢复上一轮产物")
}

// Run 启动 HTTP 服务与定时探测循环，直到 ctx 取消。
func (a *App) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handle)
	mux.HandleFunc("/api/refresh-status", a.admin(a.handleRefreshStatus))
	mux.HandleFunc("/api/dns", a.admin(a.handleDNSStats))
	mux.HandleFunc("/api/update-check", a.admin(a.handleUpdateCheck))
	srv := &http.Server{
		Addr: ":" + a.port, Handler: mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	// 容量 2：HTTP 与 DNS 应答器两个生产者，避免任一方的错误阻塞导致 goroutine 泄漏。
	errCh := make(chan error, 2)
	a.errCh = errCh
	a.dnsBaseCtx = ctx
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	log.Printf("HTTP 服务已启动，监听 :%s", a.port)
	// DNS 监听失败属致命错误：返回后进程退出，由 init 系统的 Restart=always 拉起。
	a.ensureDNSServerStarted()
	// 健康探针：定时只测当前 IP，失效/变慢时触发即时轮次，把故障发现延迟降到分钟级。
	go a.watchLoop(ctx)
	// 子域扩展缓存清扫：定期清理过期与已不在配置中的条目，兜住惰性清理漏掉的泄漏。
	go a.expandSweeper(ctx)
	// 新版本检查：启动后异步查一次 GitHub releases/latest，随后每小时复检。
	go a.updateChecker.Run(ctx)

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

// errRoundBusy 表示轮次锁在限时内未拿到：周期任务应跳过本 tick，
// 用户显式操作应返回 409 由其决定重试时机。
var errRoundBusy = errors.New("轮次锁繁忙，暂未拿到探测锁")

// roundBudget 是单轮探测的整体预算。上限 15 分钟：单个异常轮次被此保险丝截断，
// 避免把看门狗、手动刷新等所有入口全部堵在轮次锁上；下限 2 分钟：正常一轮
// （几十秒）有充足余量吸收上游 DNS 拖长、候选面全灭升级全量等尾部情况。
func roundBudget(scheduleMinutes int) time.Duration {
	if scheduleMinutes < 2 {
		scheduleMinutes = 2
	}
	if scheduleMinutes > 15 {
		scheduleMinutes = 15
	}
	return time.Duration(scheduleMinutes) * time.Minute
}

// doRound 执行一轮全量探测（定时轮次，复用子域扩展缓存）。
func (a *App) doRound(ctx context.Context) (int, error) {
	return a.doRoundFor(ctx, nil, false, 5*time.Minute)
}

// doRoundFor 执行一轮；only 非空时只刷新指定域名，并把结果合并回现有快照。
// forceExpand 为真时整轮强制重新展开子域名（手动 /refresh 语义：用户主动刷新视为要最新发现）。
// lockWait 是拿轮次锁的等待上限：0 表示拿不到立即跳过；周期任务传较长上限、
// 拿不到跳过本 tick；用户显式操作传短上限、拿不到返回 errRoundBusy（调用方映射为 409）。
// 每轮重新读取 domains.json，因此手动增删域名后下一轮自动生效，无需重启。
func (a *App) doRoundFor(ctx context.Context, only map[string]bool, forceExpand bool, lockWait time.Duration) (int, error) {
	if !a.roundMu.tryLockTimeout(lockWait) {
		a.lockBusyCount.Add(1)
		log.Printf("轮次锁繁忙，未获取到探测锁（等待上限 %v）", lockWait)
		return a.lastSchedule, errRoundBusy
	}
	defer a.roundMu.unlock()

	rt, err := config.Load()
	if err != nil {
		log.Printf("配置加载失败（保留上一轮产物）: %v", err)
		a.roundLastStatus.Store("error")
		return a.lastSchedule, err
	}
	a.lastSchedule = rt.Config.Defaults.ScheduleMinutes
	d := rt.Config.Defaults
	// 整轮预算：拿锁等待不计入，只约束探测本身。超时即整轮作废，保留上一轮产物。
	roundCtx, cancel := context.WithTimeout(ctx, roundBudget(d.ScheduleMinutes))
	defer cancel()
	ctx = roundCtx
	// DNS 应答器的 TTL 与分流域名清单每轮跟随配置，改完 domains.json 下一轮生效。
	a.dnsTTL.Store(int64(d.DNS.TTL))
	a.applyDNSListen(d.DNS.Listen)
	a.updateDNSFamilies(rt.Config.Domains)
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
			for _, sub := range a.expandSubdomains(ctx, t, d, forceExpand) {
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

	// 整轮共用一个并发池：域名之间不再串行，某个域名吃满额度时其他域名可以继续跑。
	// 探测结果按域名名排序，保证产物顺序稳定（避免每次轮次的 hosts.txt 行序都在变）。
	sem := make(chan struct{}, d.Concurrency)
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		entries []output.Entry
	)
	for _, t := range targets {
		wg.Add(1)
		go func(t config.Target) {
			defer wg.Done()
			entry := a.probeDomain(ctx, t, d, sem)
			mu.Lock()
			entries = append(entries, entry)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	// 超时即整轮作废：不做部分合并（部分域名条目会让产物半新半旧），
	// 不换快照、不写历史，保留上一轮产物。
	if ctx.Err() != nil {
		a.roundTimeoutCount.Add(1)
		a.roundLastStatus.Store("timeout")
		log.Printf("本轮超时作废，保留上一轮产物: %v", ctx.Err())
		return d.ScheduleMinutes, ctx.Err()
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

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
	round := output.RoundInfo{
		StartedAt: started, FinishedAt: now, OK: true,
		ScheduleMinutes: d.ScheduleMinutes,
		RoundID:         a.roundSeq.Add(1),
	}
	a.appendHistory(refreshed, now, fmt.Sprintf("r%d", a.roundSeq.Load()))
	// 全量轮末尾修剪 state.json：删除配置中已不存在域名的状态条目。
	// 仅全量轮（only==nil）执行，按本轮启动时的配置快照判定（含禁用域名——其候选/IP
	// 对重新启用有价值，保留与现有行为一致）。键归一比对，避免大小写混写误删。
	if only == nil {
		a.pruneStateDomains(parsedDomainSet(rt.Config.Domains))
	}
	a.stateMu.Lock()
	stateData := a.state.Snapshot(now)
	a.stateMu.Unlock()
	a.state.SaveAsync(a.statePath, stateData)
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
	a.applyDNSSnapshot(snap)
	a.roundDurationMs.Store(time.Since(started).Milliseconds())
	a.roundLastStatus.Store("ok")
	log.Printf("本轮完成：%d/%d 个域名生效，产物已写入 %s", snap.Status.ActiveCount, len(entries), filepath.Dir(a.hostsPath))
	return d.ScheduleMinutes, nil
}

// probeDomain 对单个域名完成「采集 → 测速 → 决策」，返回本轮条目。
// sem 是整轮共享的并发信号量，所有域名共用，避免某个域名吃满额度。
func (a *App) probeDomain(ctx context.Context, t config.Target, d config.Defaults, sem chan struct{}) output.Entry {
	ips := a.collectCandidates(ctx, t, d)

	checker := probe.New(probe.Options{
		SNI: t.SNI, Port: t.Port, Rounds: d.TCPRounds,
		Timeout: time.Duration(d.TimeoutSeconds) * time.Second, RootCAs: a.rootCAs,
		ExpectStatus: t.ExpectStatus,
	})

	// 自适应探测面：常规轮次只测「当前 IP + 前 N 个挑战者」，每 K 轮做一次全量扫描，
	// 在省下每轮几十次连接的同时保留发现新 IP 的通道。
	set := probeSet(ips, a.domainState(t.Name), d.ProbeTopN, d.ProbeFullEvery, a.roundSeq.Load())
	results := probe.ProbeAll(ctx, set, checker, sem)
	if len(results) == 0 && len(ips) > len(set) && ctx.Err() == nil {
		// 常规探测面全灭时升级为全量：否则会把「候选面里还有可用 IP」误判成整轮全灭，
		// 一直沿用已经失效的旧 IP，直到下一次全量扫描。超时预算已耗尽时不再升级，
		// 避免白白再打一轮全量烧预算。
		log.Printf("[%s] 常规探测面全灭，升级为全量扫描（%d 个候选）", t.Name, len(ips))
		results = probe.ProbeAll(ctx, ips, checker, sem)
	}

	cands := make([]store.Candidate, 0, len(results))
	for _, r := range results {
		cands = append(cands, store.Candidate{IP: r.IP, LatencyMS: r.LatencyMS})
	}
	a.stateMu.Lock()
	dec := a.state.Decide(t.Name, cands, d.HysteresisPercent, d.HysteresisRounds, time.Now())
	a.stateMu.Unlock()

	entry := output.Entry{
		Name: t.Name, IP: dec.IP, LatencyMS: dec.LatencyMS,
		Reason: dec.Reason, Validated: dec.Validated,
		Candidates: len(ips),
	}
	log.Printf("[%s] 候选 %d → 探测面 %d → 校验通过 %d → 生效 %q（%s）", t.Name, len(ips), len(set), len(results), dec.IP, dec.Reason)
	return entry
}

// collectCandidates 取某域名的候选 IP：配置里显式给出的候选优先，否则向上游 DNS 采集。
func (a *App) collectCandidates(ctx context.Context, t config.Target, d config.Defaults) []string {
	if len(t.Candidates) > 0 {
		return t.Candidates
	}
	ips, err := dnsquery.CollectWithOptions(ctx, t.Name, d.ProbeDNS, dnsquery.Options{
		Timeout:      time.Duration(d.TimeoutSeconds) * time.Second,
		AllowPrivate: t.AllowPrivate, Limit: d.MaxCandidates, RootCAs: a.rootCAs,
	})
	if err != nil {
		log.Printf("[%s] DNS 采集失败: %v", t.Name, err)
	}
	return ips
}

// domainState 在 stateMu 读锁下取某域名的状态副本，供探测面决策使用。
func (a *App) domainState(name string) *store.DomainState {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	st := a.state.AllDomains()[name]
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
}

// probeSet 决定本轮要探测的候选集合。
//
//	首次探测、每 ProbeFullEvery 轮、或候选数不超过上限：全量扫描。
//	其余轮次：当前生效 IP + 历史候选里延迟最低的 ProbeTopN 个。
func probeSet(ips []string, st *store.DomainState, topN, fullEvery int, roundSeq int64) []string {
	if len(ips) == 0 {
		return nil
	}
	if topN <= 0 {
		topN = 5
	}
	if fullEvery <= 1 || st == nil || st.IP == "" || len(ips) <= topN+1 || roundSeq%int64(fullEvery) == 0 {
		return ips
	}
	set := make([]string, 0, topN+1)
	seen := make(map[string]bool, topN+1)
	if st.IP != "" {
		set = append(set, st.IP)
		seen[st.IP] = true
	}
	// 状态里保存的候选已按延迟升序（ProbeAll 的输出顺序），取前 N 个挑战者。
	for _, c := range st.Candidates {
		if len(set) >= topN+1 {
			break
		}
		if seen[c.IP] {
			continue
		}
		seen[c.IP] = true
		set = append(set, c.IP)
	}
	return set
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
			Validated: s.Validated, Candidates: s.Candidates,
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

// pruneStateDomains 删除不在 keep 集合中的域名状态。
// 键先做小写+去空格归一：Decide 的键保留配置原文大小写，直接比对会漏删或误删。
func (a *App) pruneStateDomains(keep map[string]bool) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	for name := range a.state.Domains {
		norm := strings.ToLower(strings.TrimSpace(name))
		if !keep[norm] {
			delete(a.state.Domains, name)
		}
	}
	a.stateDomainsSize.Store(int64(len(a.state.Domains)))
}

func (a *App) handle(w http.ResponseWriter, r *http.Request) {
	if adminPaths[r.URL.Path] && !a.checkAdmin(w, r) {
		return
	}
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
	case "/healthz":
		a.handleHealthz(w, r)
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
		// 本轮全灭时磁盘上还保留着上一轮产物：服务它，而不是返回 503，
		// 否则订阅端会因为拿不到内容而丢掉仍然可用的旧规则。
		if data, etag, ok := a.retainedProduct(kind); ok {
			writeProduct(w, r, data, etag, contentType, snap.Modified)
			return
		}
		http.Error(w, "尚无有效 IP：请检查 domains.json 的域名/候选，或 POST /refresh 重试；失败时保留上一轮结果", http.StatusServiceUnavailable)
		return
	}
	writeProduct(w, r, data, etag, contentType, snap.Modified)
}

// retainedProduct 读取磁盘上保留的上一轮产物（本轮没有可用 IP 时的兜底）。
func (a *App) retainedProduct(kind string) ([]byte, string, bool) {
	path := a.hostsPath
	if kind == "agh" {
		path = a.aghPath
	}
	if !util.Exists(path) {
		return nil, "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}
	return b, output.ETag(b), true
}

// writeProduct 写出产物并附带 ETag / Last-Modified，支持条件请求。
func writeProduct(w http.ResponseWriter, r *http.Request, data []byte, etag, contentType string, mod time.Time) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
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
	taskID, reused, throttled := a.startRefresh(names)
	if throttled {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"ok": false, "error": "刷新过于频繁，请 10 秒后再试",
		})
		return
	}
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
// 返回 (taskID, reused, throttled)：throttled=true 表示距上次刷新不足最小间隔，应回 429。
func (a *App) startRefresh(domains []string) (string, bool, bool) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()
	if a.refreshTask != nil && a.refreshTask.State == refreshRunning {
		return a.refreshTask.ID, true, false
	}
	if time.Since(a.lastRefresh) < refreshMinInterval {
		return "", false, true
	}
	task := &refreshTask{
		ID:        fmt.Sprintf("r%d", time.Now().UnixNano()),
		State:     refreshRunning,
		StartedAt: time.Now(),
		Domains:   domains,
	}
	a.refreshTask = task
	a.lastRefresh = time.Now()
	go a.runRefresh(task, domains)
	return task.ID, false, false
}

// refreshLockWait 是后台刷新任务拿轮次锁的等待上限。整轮预算上限 15 分钟，
// 再加 2 分钟余量保证排队的正常轮次能完成；拿不到锁说明锁被异常占用，
// 任务置为失败让前端看到明确状态而非永远 running。
const refreshLockWait = 17 * time.Minute

// runRefresh 执行后台轮次并回填任务状态。
// 使用独立 context：请求结束后探测不应被取消，各阶段仍有自身的超时控制。
func (a *App) runRefresh(task *refreshTask, domains []string) {
	var minutes int
	var err error
	if len(domains) == 0 {
		// 手动整轮刷新视为用户要最新发现：强制重新展开子域名，绕过 TTL 缓存。
		minutes, err = a.doRoundFor(context.Background(), nil, true, refreshLockWait)
	} else {
		only := make(map[string]bool, len(domains))
		for _, name := range domains {
			only[name] = true
		}
		minutes, err = a.doRoundFor(context.Background(), only, false, refreshLockWait)
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
		// 监听地址必须与分流行同步：保存即重绑，规则随实际监听地址一起变化。
		a.applyDNSListen(parsed.Defaults.DNS.Listen)
		// 域名增删后即时回收展开缓存：删除的域名不再重展开，避免条目长期残留。
		a.evictExpandCacheExcept(parsedDomainSet(parsed.Domains))
		// 增删域名后即时刷新 AGH 上游分流行，避免用户已删除的域名仍被分流过来。
		a.refreshDNSFamiliesFromConfig()
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
//
// 缓存语义：非强制刷新时先查缓存，TTL 内命中直接复用；展开成功且非空才写缓存，
// 失败或结果为空不写。forceRefresh（手动 /refresh 整轮）绕过缓存并清掉该域名的旧条目，
// 保证用户主动刷新拿到的是最新发现。
func (a *App) expandSubdomains(ctx context.Context, t config.Target, d config.Defaults, forceRefresh bool) []config.Target {
	sources, err := parseExpandSources(t.ExpandSources)
	if err != nil {
		log.Printf("[%s] 展开来源配置非法，已跳过: %v", t.Name, err)
		return nil
	}
	timeout := time.Duration(t.ExpandTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	opts := expand.Options{
		Sources:       sources,
		Concurrency:   t.ExpandConcurrency,
		Timeout:       timeout,
		MaxSubdomains: t.ExpandMaxSubdomains,
		ProbeDNS:      d.ProbeDNS,
	}

	if forceRefresh {
		a.expandCacheEvict(t.Name)
	} else if results, ok := a.expandCacheGet(t.Name, opts, d.ExpandCacheTTLHours); ok {
		subs := buildSubTargets(t, results)
		if len(subs) > 0 {
			log.Printf("[%s] 子域展开命中缓存：%d 个子域名复用", t.Name, len(subs))
		}
		return subs
	}

	expandCtx, cancel := context.WithTimeout(ctx, timeout+timeout/2)
	defer cancel()
	results, err := expand.New(opts).Expand(expandCtx, t.Name)
	if err != nil {
		log.Printf("[%s] 域名展开失败: %v", t.Name, err)
		return nil
	}
	subs := buildSubTargets(t, results)
	if len(subs) > 0 {
		a.expandCachePut(t.Name, opts, results)
		log.Printf("[%s] 域名展开：%d 个子域名可解析", t.Name, len(subs))
	}
	return subs
}

// buildSubTargets 把展开结果里的可解析子域名转成待探测目标。
// 基础参数（端口/SNI/期望状态等）始终取当轮 t，缓存命中时也不会沿用过期配置。
func buildSubTargets(t config.Target, results []expand.Result) []config.Target {
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
	return subs
}

// expandFingerprint 计算影响展开结果的参数指纹：来源、并发、子域上限、探测 DNS 任一变化
// 都会让缓存条目失效，避免配置改了仍复用旧结果。
func expandFingerprint(o expand.Options) string {
	srcs := append([]expand.Source(nil), o.Sources...)
	sort.Slice(srcs, func(i, j int) bool { return srcs[i] < srcs[j] })
	return fmt.Sprintf("%v|%d|%d|%v", srcs, o.Concurrency, o.MaxSubdomains, o.ProbeDNS)
}

// expandCacheGet 命中返回缓存的子域名结果；未命中/过期/指纹不符返回 false 并计 miss。
func (a *App) expandCacheGet(domain string, o expand.Options, ttlHours int) ([]expand.Result, bool) {
	a.expandCacheMu.Lock()
	defer a.expandCacheMu.Unlock()
	if a.expandCache == nil {
		a.expandMisses.Add(1)
		return nil, false
	}
	e, ok := a.expandCache[domain]
	if !ok || e.fingerprint != expandFingerprint(o) {
		a.expandMisses.Add(1)
		return nil, false
	}
	if ttlHours > 0 && time.Since(e.savedAt) >= time.Duration(ttlHours)*time.Hour {
		a.expandMisses.Add(1)
		return nil, false
	}
	a.expandHits.Add(1)
	return e.results, true
}

// expandCachePut 写入/刷新一条缓存。结果按「展开器返回顺序」保存，不做子域去重以外的处理。
func (a *App) expandCachePut(domain string, o expand.Options, results []expand.Result) {
	a.expandCacheMu.Lock()
	defer a.expandCacheMu.Unlock()
	if a.expandCache == nil {
		a.expandCache = map[string]expandCacheEntry{}
	}
	a.expandCache[domain] = expandCacheEntry{
		fingerprint: expandFingerprint(o),
		results:     results,
		savedAt:     time.Now(),
	}
	a.expandCacheSize.Store(int64(len(a.expandCache)))
}

// expandCacheEvict 删除某域名的缓存条目（手动刷新强制重展开时调用）。
func (a *App) expandCacheEvict(domain string) {
	a.expandCacheMu.Lock()
	defer a.expandCacheMu.Unlock()
	delete(a.expandCache, domain)
	a.expandCacheSize.Store(int64(len(a.expandCache)))
}

// expandSweepInterval 是扩展缓存后台清扫的周期。条目量级是「域名数 × 一次性展开结果」，
// 泄漏增长极慢，30 分钟粒度足够；清扫本身持锁时间微秒级，不与探测轮竞争。
const expandSweepInterval = 30 * time.Minute

// parsedDomainSet 返回配置中域名名（原文 + 小写）的集合。缓存与退避状态的键
// 大小写不保证归一，修剪时用两套键同时匹配，避免大小写混写误判为「已删除」。
func parsedDomainSet(domains []config.Domain) map[string]bool {
	set := make(map[string]bool, len(domains)*2)
	for _, dom := range domains {
		name := strings.TrimSpace(dom.Name)
		if name == "" {
			continue
		}
		set[name] = true
		set[strings.ToLower(name)] = true
	}
	return set
}

// expandSweeper 定期清扫扩展缓存：删除「已不在配置中」与「超过 TTL」的条目。
// 惰性 TTL 检查只在读取时发生，直接删域名或改 JSON 文件的路径无人调用 Evict，
// 此清扫兜住这些漏网路径，保证缓存条目数有界。
func (a *App) expandSweeper(ctx context.Context) {
	ticker := time.NewTicker(expandSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		rt, err := config.Load()
		if err != nil {
			continue
		}
		a.sweepExpandCache(parsedDomainSet(rt.Config.Domains), rt.Config.Defaults.ExpandCacheTTLHours)
	}
}

// sweepExpandCache 删除不在配置中或超过 TTL 的缓存条目。
func (a *App) sweepExpandCache(active map[string]bool, ttlHours int) {
	a.expandCacheMu.Lock()
	defer a.expandCacheMu.Unlock()
	for name, e := range a.expandCache {
		if !active[name] || (ttlHours > 0 && time.Since(e.savedAt) >= time.Duration(ttlHours)*time.Hour) {
			delete(a.expandCache, name)
		}
	}
	a.expandCacheSize.Store(int64(len(a.expandCache)))
}

// evictExpandCacheExcept 删除不在 keep 集合中的缓存条目（配置写路径即时回收）。
// 只删「配置里彻底消失的」；禁用的域名条目保留，TTL 到期由清扫兜底。
func (a *App) evictExpandCacheExcept(keep map[string]bool) {
	a.expandCacheMu.Lock()
	defer a.expandCacheMu.Unlock()
	for name := range a.expandCache {
		if !keep[name] {
			delete(a.expandCache, name)
		}
	}
	a.expandCacheSize.Store(int64(len(a.expandCache)))
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
	st := a.state.AllDomains()[domain]
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

	if !a.roundMu.tryLockTimeout(2*time.Second) {
		a.lockBusyCount.Add(1)
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "当前有探测轮次进行中，请稍后重试"})
		return
	}
	defer a.roundMu.unlock()
	now := time.Now()

	a.stateMu.Lock()
	st := a.state.AllDomains()[domain]
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
	stateData := a.state.Snapshot(now)
	candidateCount := len(st.Candidates)
	a.stateMu.Unlock()
	a.state.SaveAsync(a.statePath, stateData)

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
		RoundID:         a.roundSeq.Add(1),
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
	a.applyDNSSnapshot(built)
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
	if !a.roundMu.tryLockTimeout(2*time.Second) {
		a.lockBusyCount.Add(1)
		return 0, errRoundBusy
	}
	defer a.roundMu.unlock()
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
		RoundID:         a.roundSeq.Add(1),
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
	// 就地改 a.snap 会让并发读 /agh.txt 的请求看到「新内容配旧 ETag」
	// （serve 取字段不在同一临界区）。改为整对象替换一个浅拷贝。
	a.mu.Lock()
	if cur := a.snap; cur != nil {
		next := *cur
		next.AGH = built.AGH
		next.AGHETag = built.AGHETag
		next.Modified = now
		a.snap = &next
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
		switch {
		case errors.Is(err, errNoSnapshot):
			code = http.StatusServiceUnavailable
		case errors.Is(err, errNoValidIP), errors.Is(err, errRoundBusy):
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": n})
}

// handleHealthz 健康检查端点，供容器编排/负载均衡探活。
func (a *App) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET / HEAD"})
		return
	}
	a.mu.RLock()
	snap := a.snap
	a.mu.RUnlock()
	resp := map[string]any{
		"ok":       true,
		"version":  a.version,
		"uptime":   time.Since(a.startedAt).String(),
		"data_dir": a.dataDir,
	}
	// 子域扩展缓存命中情况，便于确认缓存是否按预期工作。
	resp["expand_cache_hits"] = a.expandHits.Load()
	resp["expand_cache_misses"] = a.expandMisses.Load()
	// 新版本检查状态（HO_UPDATE_CHECK=off 时 latest 为空、available=false）。
	latest, available, checkedAt := a.updateChecker.Status()
	resp["update_available"] = available
	resp["latest_version"] = latest
	if !checkedAt.IsZero() {
		resp["update_checked_at"] = checkedAt.Format(time.RFC3339)
	}
	if snap != nil {
		resp["dns_enabled"] = a.dnsSrv != nil
		resp["last_round"] = snap.Status.GeneratedAt.Format(time.RFC3339)
	}
	// 长期运行观测：轮次耗时与状态、超时/锁排队计数、各缓存规模。
	resp["round_duration_ms"] = a.roundDurationMs.Load()
	resp["round_last_status"] = a.roundLastStatus.Load()
	resp["round_timeout_count"] = a.roundTimeoutCount.Load()
	resp["round_lock_busy"] = a.lockBusyCount.Load()
	resp["expand_cache_size"] = a.expandCacheSize.Load()
	resp["watch_states_size"] = a.watchStatesSize.Load()
	resp["state_domains_size"] = a.stateDomainsSize.Load()
	for k, v := range a.watchdogStats() {
		resp[k] = v
	}
	writeJSON(w, http.StatusOK, resp)
}

// watchdogStats 汇总健康探针的可观测信息，挂在公开的 /healthz 上便于排查
// 「为什么一直在触发即时轮次」这类问题。
func (a *App) watchdogStats() map[string]any {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	out := map[string]any{"watch_triggered": len(a.watchStates)}
	if !a.watchLastCheck.IsZero() {
		out["watch_last_check"] = a.watchLastCheck.Format(time.RFC3339)
	}
	if len(a.watchLastDegraded) > 0 {
		out["watch_last_degraded"] = a.watchLastDegraded
	}
	if len(a.watchLastTriggered) > 0 {
		out["watch_last_triggered"] = a.watchLastTriggered
	}
	return out
}

// updateCheckMinInterval 是手动检查更新的最小间隔，防刷导致 GitHub 请求风暴。
const updateCheckMinInterval = 60 * time.Second

// handleUpdateCheck 手动触发一次版本检查（界面「关于」面板的「检查更新」按钮）。
// 60 秒内重复触发返回 429；调用已存在的 Checker.Check/Status，不引入新的检查逻辑。
func (a *App) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST"})
		return
	}
	a.updateCheckMu.Lock()
	if time.Since(a.lastUpdateCheck) < updateCheckMinInterval {
		a.updateCheckMu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "检查过于频繁，请 60 秒后再试"})
		return
	}
	a.lastUpdateCheck = time.Now()
	a.updateCheckMu.Unlock()

	a.updateChecker.Check(r.Context())
	latest, available, checkedAt := a.updateChecker.Status()
	resp := map[string]any{
		"ok":               true,
		"latest_version":   latest,
		"update_available": available,
	}
	if !checkedAt.IsZero() {
		resp["checked_at"] = checkedAt.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
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

	if !a.roundMu.tryLockTimeout(5*time.Second) {
		a.lockBusyCount.Add(1)
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "当前有探测轮次进行中，请稍后重试"})
		return
	}
	defer a.roundMu.unlock()

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

	// 家族清单必须即时跟随：禁用后若仍留在 AGH 上游行里，AGH 会把查询送来，
	// 而我们对该域名答 REFUSED，等于把用户网络解析搞挂。
	a.refreshDNSFamiliesFromConfig()
	// 域名集合变化后即时回收展开缓存（用已写盘配置的域名集合判定）。
	if rt, err := config.Load(); err == nil {
		a.evictExpandCacheExcept(parsedDomainSet(rt.Config.Domains))
	}
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
		RoundID:         a.roundSeq.Add(1),
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
	a.applyDNSSnapshot(built)
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

var indexTmpl = ui.Template()

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
	// 接入模式与配置单一事实来源保持一致：dns.listen 为空即订阅模式。
	mode := "dns"
	if rt, err := config.Load(); err == nil {
		if strings.TrimSpace(rt.Config.Defaults.DNS.Listen) == "" {
			mode = "subscribe"
		}
	}
	data := struct {
		GeneratedAt     string
		ScheduleMinutes int
		ActiveCount     int
		DomainCount     int
		Ready           bool
		Mode            string
		Domains         []domainView
		Version         string
		ProjectURL      string
		DNSTTL          int
	}{
		GeneratedAt:     snap.Status.GeneratedAt.Format(time.RFC3339),
		ScheduleMinutes: snap.Status.ScheduleMinutes,
		ActiveCount:     active,
		DomainCount:     len(views),
		Ready:           active > 0,
		Mode:            mode,
		Domains:         views,
		Version:         a.version,
		ProjectURL:      "https://github.com/wulinwei959/ip-optimizer",
		DNSTTL:          int(a.dnsTTL.Load()),
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
