// Package util 提供产物与状态文件的原子写。
package util

import (
	"fmt"
	"os"
	"path/filepath"
)

// AtomicWrite 先写同目录临时文件，sync 后 rename，保证订阅端不会读到半个文件。
func AtomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("创建目录 %s 失败: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".ho-*")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("原子替换 %s 失败: %w", path, err)
	}
	return nil
}

// Exists 判断文件是否存在。
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
