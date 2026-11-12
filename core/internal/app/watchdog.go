package app

import (
	"context"
	"crypto/x509"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"hosts-optimizer/internal/config"
	"hosts-optimizer/internal/probe"
	"hosts-optimizer/internal/store"
)

// maxWatchBackoff 是单个域名退避间隔的上限。
const maxWatchBackoff = 30 * time.Minute

// watchState 是单个域名在健康探针上的退避状态。
type watchState struct {
	last    time.Time
	backoff time.Duration
}

// watchTarget 是健康探针要检查的一个域名：只测它的当前生效 IP。
type watchTarget struct {
	Name string
	IP   string
	SNI  string
	Port int
	// BaselineLatencyMS 是「当前 IP 自己」上一轮的实测延迟，用作变慢判断的基准。
	// 用它而不是候选里最快的一次，否则当前 IP 本来就不是最优时会被一直误判为变慢。
	BaselineLatencyMS float64
}

// watchLoop 定期只测一次「当前生效 IP」：一旦失效或明显变慢，立即触发一次小轮次。
// 没有它的话，故障要等下一个整轮（默认 60 分钟）才被发现，期间用户一直在用坏 IP。
func (a *App) watchLoop(ctx context.Context) {
	for {
		rt, err := config.Load()
		if err != nil {
			// 配置读不出来时按固定间隔退避，避免空转刷屏。
			if !sleepCtx(ctx, 60*time.Second) {
				return
			}
			continue
		}
		interval := time.Duration(rt.Config.Defaults.WatchIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 60 * time.Second
		}
		if !sleepCtx(ctx, interval) {
			return
		}
		a.watchOnce(ctx, rt, interval)
	}
}

// sleepCtx 等待 d；ctx 取消时返回 false。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// watchOnce 跑一轮健康检查，必要时触发即时轮次。
func (a *App) watchOnce(ctx context.Context, rt *config.Runtime, interval time.Duration) {
	d := rt.Config.Defaults
	targets := a.watchTargets(rt.Config)
	if len(targets) == 0 {
		return
	}
	degraded := checkCurrentIPs(ctx, targets, d, a.rootCAs)
	if len(degraded) == 0 {
		// 本轮所有 targets 都健康：清掉它们的退避状态，下次触发自然回落基础退避。
		// 未进 targets（无生效 IP）的域名不动——它们不是健康，只是不可测。
		a.resetWatchBackoff(targets)
		return
	}

	degradedNames := make([]string, 0, len(degraded))
	for _, t := range degraded {
		degradedNames = append(degradedNames, t.Name)
	}
	sort.Strings(degradedNames)

	// 基础退避：当前 IP 一直失效、而整轮又找不到替代时，没必要每个探测周期都跑一轮。
	// 触发后若没能换掉 IP（只是抖动），退避会按指数继续翻倍。
	baseBackoff := interval * 3
	if baseBackoff <= 0 {
		baseBackoff = 3 * time.Minute
	}
	now := time.Now()
	a.setWatchCheck(degradedNames, now)

	only := make(map[string]bool, len(degraded))
	before := make(map[string]string, len(degraded))
	names := make([]string, 0, len(degraded))
	for _, t := range degraded {
		if !a.shouldTriggerWatch(t.Name, now, baseBackoff) {
			continue
		}
		only[t.Name] = true
		before[t.Name] = t.IP
		names = append(names, t.Name)
	}
	if len(only) == 0 {
		return
	}
	sort.Strings(names)

	// 与定时轮次共用轮次锁：拿不到（上一轮异常长）时立即跳过本次检查，
	// 不排队等待——下一个 watch interval 会重新发现 degraded，无正确性损失。
	// forceExpand=false：定向轮次本就不展开子域名，缓存与否无关。
	if _, err := a.doRoundFor(ctx, only, false, 0); err != nil {
		log.Printf("健康探针触发的轮次失败（%s）: %v", strings.Join(names, ","), err)
		return
	}
	// 这次即时轮次真的换掉了 IP，说明探针抓到了真问题，恢复正常节奏；
	// 没换掉说明当前 IP 只是抖动（轮次里能过、探针里过不了），退避翻倍，
	// 免得每个探测周期都白跑一轮。
	changed := make(map[string]bool, len(names))
	for _, n := range names {
		changed[n] = a.currentIP(n) != before[n]
	}
	a.markTriggered(names, now, baseBackoff, changed)
	a.setWatchTriggered(names)
	log.Printf("健康探针触发即时轮次: %s", strings.Join(names, ","))
}

// shouldTriggerWatch 判断是否到了可以再次触发即时轮次的时间。
func (a *App) shouldTriggerWatch(name string, now time.Time, base time.Duration) bool {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	st, ok := a.watchStates[name]
	return !ok || now.Sub(st.last) >= st.backoff
}

// markTriggered 记录本次触发时间与退避间隔。
func (a *App) markTriggered(names []string, now time.Time, base time.Duration, changed map[string]bool) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	if a.watchStates == nil {
		a.watchStates = map[string]watchState{}
	}
	for _, n := range names {
		st := a.watchStates[n]
		if changed[n] {
			st.backoff = base
		} else {
			next := st.backoff * 2
			if next <= 0 {
				next = base
			}
			if next > maxWatchBackoff {
				next = maxWatchBackoff
			}
			st.backoff = next
		}
		st.last = now
		a.watchStates[n] = st
	}
}

// resetWatchBackoff 删除一批域名的退避状态（健康重置）。删除而非归零：
// 下次触发自动回落到基础退避，语义等价且实现最小。
func (a *App) resetWatchBackoff(targets []watchTarget) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	for _, t := range targets {
		delete(a.watchStates, t.Name)
	}
	a.watchStatesSize.Store(int64(len(a.watchStates)))
}

// currentIP 读取某域名当前生效的 IP。
func (a *App) currentIP(name string) string {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	st := a.state.AllDomains()[name]
	if st == nil {
		return ""
	}
	return st.IP
}

// setWatchCheck 记录最近一次健康检查的结果，供 /healthz 展示。
func (a *App) setWatchCheck(degraded []string, at time.Time) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	a.watchLastCheck = at
	a.watchLastDegraded = append([]string(nil), degraded...)
}

// setWatchTriggered 记录最近一次触发即时轮次的域名。
func (a *App) setWatchTriggered(names []string) {
	a.watchMu.Lock()
	defer a.watchMu.Unlock()
	a.watchLastTriggered = append([]string(nil), names...)
}

// watchTargets 汇总「已启用且已有生效 IP」的域名及其探测参数。
func (a *App) watchTargets(cfg config.Config) []watchTarget {
	// 修剪 watchStates：清理不在当前配置（含禁用域名，防反复加回/禁用又恢复抖动）中的
	// 残留条目。watchTargets 每 watch interval 都跑，天然是「对齐配置与运行态」的汇聚点。
	active := make(map[string]bool, len(cfg.Domains)*2)
	for _, dom := range cfg.Domains {
		name := strings.TrimSpace(dom.Name)
		if name != "" {
			active[name] = true
			active[strings.ToLower(name)] = true
		}
	}
	a.watchMu.Lock()
	for name := range a.watchStates {
		if !active[name] {
			delete(a.watchStates, name)
		}
	}
	a.watchStatesSize.Store(int64(len(a.watchStates)))
	a.watchMu.Unlock()

	a.stateMu.RLock()
	defer a.stateMu.RUnlock()

	out := make([]watchTarget, 0, len(cfg.Domains))
	for _, dom := range cfg.Domains {
		name := strings.ToLower(strings.TrimSpace(dom.Name))
		if name == "" || dom.Disabled {
			continue
		}
		st := a.state.AllDomains()[name]
		if st == nil || st.IP == "" {
			continue
		}
		// 上一轮已经确认「没有任何候选可用」时不再触发即时轮次：那时当前 IP 本来就没
		// 通过校验，再探一次结果一样，只会空转（这类域名会一直等到 DNS 答案变化，
		// 由正常轮次去发现）。刚启动、还没跑过首轮时 ValidatedLastRound 也是 0，
		// 此时跳过同样正确——首轮会立刻补上。
		if st.ValidatedLastRound == 0 {
			continue
		}
		t := cfg.Resolve(dom)
		out = append(out, watchTarget{
			Name: name, IP: st.IP, SNI: t.SNI, Port: t.Port,
			BaselineLatencyMS: baselineLatency(st),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// baselineLatency 返回当前 IP 自己上一轮的实测延迟。
// 当前 IP 不在本轮候选里（说明它是上一轮留下的、本轮没有可用替代）时返回 0：
// 这时没有可比的基准，只按「是否还活着」判断，不再拿别的 IP 的时延当基准，
// 否则会把这种域名每个探测周期都误判成「变慢」。
func baselineLatency(st *store.DomainState) float64 {
	for _, c := range st.Candidates {
		if c.IP == st.IP && c.LatencyMS > 0 {
			return c.LatencyMS
		}
	}
	return 0
}

// checkCurrentIPs 并发探测各域名的当前 IP，返回「失效或明显变慢」的目标。
//
// 取样次数与正常轮次一致（Rounds=TCPRounds）：单次取样的抖动足以越过变慢阈值，
// 会把每个探测周期都误判成「需要触发即时轮次」，等于每分钟白跑一轮。
//
// 这里只做「是否健康」的判断，不直接改产物：真正的切换交给 doRoundFor 的
// 滞回规则，避免一次抖动就换 IP。
func checkCurrentIPs(ctx context.Context, targets []watchTarget, d config.Defaults, roots *x509.CertPool) []watchTarget {
	if len(targets) == 0 {
		return nil
	}
	timeout := time.Duration(d.TimeoutSeconds) * time.Second
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var degraded []watchTarget

	for _, t := range targets {
		wg.Add(1)
		go func(t watchTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			r, err := probe.New(probe.Options{
				SNI: t.SNI, Port: t.Port, Rounds: d.TCPRounds,
				Timeout: timeout, RootCAs: roots,
			}).Check(ctx, t.IP)
			if err != nil {
				mu.Lock()
				degraded = append(degraded, t)
				mu.Unlock()
				return
			}
			if isDegraded(r, t, d.WatchSwitchPercent) {
				mu.Lock()
				degraded = append(degraded, t)
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return degraded
}

// isDegraded 判断一次当前 IP 的探测结果是否意味着需要触发即时轮次。
// 基准是当前 IP 自己上一轮的实测延迟，而不是候选里最快的一次：
// 没有历史延迟时不做「变慢」判断，只关心它是否还活着。
func isDegraded(r probe.Result, t watchTarget, percent int) bool {
	if t.BaselineLatencyMS <= 0 {
		return false
	}
	return r.LatencyMS > t.BaselineLatencyMS*(1+float64(percent)/100)
}
