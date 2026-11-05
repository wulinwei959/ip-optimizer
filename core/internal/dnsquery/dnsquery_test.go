package dnsquery

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func u16(b *bytes.Buffer, v uint16) {
	_ = binary.Write(b, binary.BigEndian, v)
}

func TestBuildQuery(t *testing.T) {
	q, err := buildQuery(0x1234, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(q[0:2]); got != 0x1234 {
		t.Fatalf("ID = %#x, want 0x1234", got)
	}
	if got := binary.BigEndian.Uint16(q[2:4]); got != 0x0100 {
		t.Fatalf("flags = %#x, want RD", got)
	}
	want := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, // QTYPE=A
		0, 1, // QCLASS=IN
	}
	if !bytes.Equal(q[12:], want) {
		t.Fatalf("question 段不符\n got: %v\nwant: %v", q[12:], want)
	}
}

// 构造一个带 0xC0 压缩指针的真实 A 应答。
func responseWithPointer(t *testing.T, id uint16) []byte {
	t.Helper()
	var b bytes.Buffer
	u16(&b, id)
	u16(&b, 0x8180) // QR + RD + RA, rcode=0
	u16(&b, 1)      // QDCOUNT
	u16(&b, 1)      // ANCOUNT
	u16(&b, 0)
	u16(&b, 0)
	b.Write([]byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1})
	b.Write([]byte{0xC0, 0x0C})                    // NAME 指针 → offset 12
	b.Write([]byte{0, 1, 0, 1, 0, 0, 0, 60, 0, 4}) // TYPE=A CLASS=IN TTL=60 RDLENGTH=4
	b.Write([]byte{93, 184, 216, 34})              // 93.184.216.34
	return b.Bytes()
}

func TestParseAResponseWithCompressionPointer(t *testing.T) {
	ips, err := parseAResponse(responseWithPointer(t, 0x1234), 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("解析结果 = %v, want [93.184.216.34]", ips)
	}
}

func TestParseAResponseRejectsMismatchedID(t *testing.T) {
	if _, err := parseAResponse(responseWithPointer(t, 0x1234), 0x9999); err == nil {
		t.Fatal("ID 不匹配时应报错")
	}
}

func TestParseAResponseRejectsRcode(t *testing.T) {
	msg := responseWithPointer(t, 0x1234)
	msg[3] = 0x83 // rcode=3 NXDOMAIN
	if _, err := parseAResponse(msg, 0x1234); err == nil {
		t.Fatal("NXDOMAIN 时应报错")
	}
}

func TestUsableFiltersPollutedAddresses(t *testing.T) {
	cases := []struct {
		ip           string
		allowPrivate bool
		want         bool
	}{
		{"140.82.114.4", false, true},
		{"127.0.0.1", false, false},
		{"0.0.0.0", false, false},
		{"10.0.0.1", false, false},
		{"192.168.1.1", false, false},
		{"192.168.1.1", true, true},
		{"169.254.1.1", false, false},
		{"224.0.0.1", false, false},
		{"100.64.0.1", false, false}, // CGNAT
		{"198.18.0.1", false, false}, // 基准测试保留段
		{"203.0.113.5", false, false},
		{"255.255.255.255", false, false},
	}
	for _, c := range cases {
		if got := usable(net.ParseIP(c.ip), c.allowPrivate); got != c.want {
			t.Errorf("usable(%s, allowPrivate=%v) = %v, want %v", c.ip, c.allowPrivate, got, c.want)
		}
	}
}
