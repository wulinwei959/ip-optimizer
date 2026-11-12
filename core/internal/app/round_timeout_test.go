package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hosts-optimizer/internal/output"
	"hosts-optimizer/internal/store"
)

// 整轮预算耗尽（ctx 已取消）时，整轮作废：不换快照、不写产物、记超时统计。
func TestRoundTimeoutVoidsRound(t *testing.T) {
	dir := t.TempDir()
	cfgDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{
  "domains": [{"name": "a.com", "candidates": ["10.255.255.1"]}],
  "defaults": {
    "schedule_minutes": 60,
    "dns": {"listen": "off"}
  }
}`
	if err := os.WriteFile(filepath.Join(cfgDir, "domains.json"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HO_CONFIG", cfgDir)

	outDir := filepath.Join(dir, "out")
	stDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stDir, 0o755); err != nil {
		t.Fatal(err)
	}

	snap := &output.Snapshot{Ready: true, Modified: time.Now()}
	a := &App{
		hostsPath:     filepath.Join(outDir, "hosts.txt"),
		aghPath:       filepath.Join(outDir, "agh.txt"),
		statusPath:    filepath.Join(outDir, "status.json"),
		statePath:     filepath.Join(stDir, "state.json"),
		state:         &store.State{Domains: map[string]*store.DomainState{}},
		roundMu:       newTimedMutex(),
		snap:          snap,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 预算未开始就已耗尽
	_, err := a.doRoundFor(ctx, nil, false, time.Second)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("超时作废应返回 context.Canceled，实际 %v", err)
	}
	if a.snap != snap {
		t.Fatal("超时轮次不得替换快照，应保留上一轮产物")
	}
	if a.roundTimeoutCount.Load() != 1 {
		t.Fatalf("超时计数应为 1，实际 %d", a.roundTimeoutCount.Load())
	}
	if got, _ := a.roundLastStatus.Load().(string); got != "timeout" {
		t.Fatalf("轮次状态应为 timeout，实际 %v", got)
	}
	if _, statErr := os.Stat(filepath.Join(outDir, "hosts.txt")); !os.IsNotExist(statErr) {
		t.Fatal("超时轮次不应写入产物文件")
	}
}
