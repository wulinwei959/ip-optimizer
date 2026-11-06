package logbuf

import (
	"strings"
	"testing"
)

func TestWriteAndSnapshot(t *testing.T) {
	b := New(10)
	if _, err := b.Write([]byte("第一行\n第二行\r\n\n")); err != nil {
		t.Fatal(err)
	}
	got := b.Snapshot(0, 10)
	if len(got) != 2 {
		t.Fatalf("条目数 = %d, want 2: %+v", len(got), got)
	}
	if got[0].Text != "第一行" || got[1].Text != "第二行" {
		t.Fatalf("内容不符: %+v", got)
	}
	if b.LastSeq() != 2 {
		t.Fatalf("LastSeq = %d, want 2", b.LastSeq())
	}
}

func TestSnapshotAfter(t *testing.T) {
	b := New(10)
	_, _ = b.Write([]byte("a\nb\nc\n"))
	got := b.Snapshot(1, 10)
	if len(got) != 2 || got[0].Text != "b" || got[1].Text != "c" {
		t.Fatalf("after=1 结果不符: %+v", got)
	}
	if got := b.Snapshot(3, 10); len(got) != 0 {
		t.Fatalf("after=last 应为空: %+v", got)
	}
}

func TestRingKeepsLatest(t *testing.T) {
	b := New(3)
	_, _ = b.Write([]byte("1\n2\n3\n4\n5\n"))
	got := b.Snapshot(0, 10)
	if len(got) != 3 {
		t.Fatalf("容量 3 时应保留 3 条，实际 %d", len(got))
	}
	if got[0].Text != "3" || got[2].Text != "5" {
		t.Fatalf("保留的不是最新三条: %+v", got)
	}
}

func TestLimit(t *testing.T) {
	b := New(100)
	_, _ = b.Write([]byte(strings.Repeat("x\n", 20)))
	if got := b.Snapshot(0, 5); len(got) != 5 {
		t.Fatalf("limit=5 实际 %d", len(got))
	}
}
