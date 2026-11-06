package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseExpandSources(t *testing.T) {
	got, err := parseExpandSources([]string{"ct", "wordlist", "rules", "CT"})
	if err != nil {
		t.Fatalf("合法来源不应报错: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("应去重为 3 个来源，实际 %d 个: %v", len(got), got)
	}

	if _, err := parseExpandSources([]string{"dns"}); err == nil {
		t.Fatal("非法来源应返回错误")
	}

	empty, err := parseExpandSources(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("空列表应返回空结果且不报错，实际 %v, %v", empty, err)
	}
}

func TestHandleExpandRejectsNonPost(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodGet, "/api/expand", nil)
	rec := httptest.NewRecorder()

	a.handleExpand(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("期望 405，实际 %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Fatalf("期望 Allow: POST，实际 %q", allow)
	}
}

func TestHandleExpandRequiresJSONContentType(t *testing.T) {
	a := &App{}
	req := httptest.NewRequest(http.MethodPost, "/api/expand", strings.NewReader(`{"domain":"github.com"}`))
	rec := httptest.NewRecorder()

	a.handleExpand(rec, req)

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("期望 415，实际 %d", rec.Code)
	}
}
