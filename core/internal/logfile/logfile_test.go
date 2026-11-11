package logfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 64)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	if _, err := w.Write([]byte(strings.Repeat("a", 40))); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(strings.Repeat("b", 40))); err != nil {
		t.Fatal(err)
	}
	// 40+40 超过 64，第二次写入前应轮转：备份含 a，新文件含 b。
	old, err := os.ReadFile(filepath.Join(dir, "app.log.1"))
	if err != nil || !strings.Contains(string(old), "aaa") {
		t.Fatalf("轮转备份应含首批内容，err=%v", err)
	}
	cur, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil || !strings.Contains(string(cur), "bbb") || strings.Contains(string(cur), "aaa") {
		t.Fatalf("新日志应只含次批内容，err=%v", err)
	}
}

func TestReopenAppends(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()

	w2, err := Open(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	if _, err := w2.Write([]byte("second\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "app.log"))
	if err != nil || string(data) != "first\nsecond\n" {
		t.Fatalf("重开应追加，得到 %q err=%v", data, err)
	}
}