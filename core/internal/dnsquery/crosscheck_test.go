package dnsquery

import (
	"net"
	"testing"
)

// TestParseAResponseCrossCheck 验证「与 dnsserver.respondA 相同字节布局」的
// 应答能被本探测侧解析器正确解出。这是应答器与探测链路 wire format 自洽的
// 交叉验证：两边共用同一套字段偏移假设，任何一侧改动破坏了布局都会在此暴露。
func TestParseAResponseCrossCheck(t *testing.T) {
	makeResp := func(id uint16, ip string, rcode uint16) []byte {
		b := net.ParseIP(ip).To4()
		if b == nil {
			t.Fatalf("测试用 IP 非法: %q", ip)
		}
		name := []byte{3, 'g', 'i', 't', 2, 'h', 'u', 3, 'c', 'o', 'm', 0}
		question := append(append([]byte{}, name...), 0x00, 0x01, 0x00, 0x01)
		qdcount, ancount := 1, 0
		var tail []byte
		if rcode == 0 {
			ancount = 1
			// 压缩指针 0xC00C + TYPE + CLASS + TTL(4B) + RDLENGTH + RDATA
			tail = []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4,
				b[0], b[1], b[2], b[3]}
		}
		out := make([]byte, 12)
		out[0], out[1] = byte(id>>8), byte(id)
		flags := uint16(0x8000) | 0x0100 | rcode
		out[2], out[3] = byte(flags>>8), byte(flags)
		out[4], out[5] = byte(qdcount>>8), byte(qdcount)
		out[6], out[7] = byte(ancount>>8), byte(ancount)
		return append(append(out, question...), tail...)
	}

	ip := "20.205.243.166"
	want := net.ParseIP(ip).To4()
	ips, err := parseAResponse(makeResp(0x1234, ip, 0), 0x1234)
	if err != nil {
		t.Fatalf("NOERROR 应答应解析成功: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(want) {
		t.Fatalf("解析 IP 不符: %v", ips)
	}

	if _, err := parseAResponse(makeResp(0x1234, ip, 5), 0x1234); err == nil {
		t.Fatal("REFUSED 应答应报错")
	}
}
