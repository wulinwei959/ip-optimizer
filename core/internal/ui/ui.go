// Package ui 提供管理页面的 HTML 模板。
//
// 模板单独成文件、用 go:embed 打进二进制，而不是内联在 app.go 里：
// 两千余行的内联字符串既没法拆分，也让每次页面改动都变成一次几十 KB 的 diff，
// review 时几乎看不到真正的改动。
package ui

import (
	_ "embed"
	"html/template"
)

//go:embed index.html
var indexHTML string

var indexTmpl = template.Must(template.New("index").Parse(indexHTML))

// Template 返回解析好的首页模板（进程内只解析一次，语法错误在启动期就暴露）。
func Template() *template.Template {
	return indexTmpl
}
