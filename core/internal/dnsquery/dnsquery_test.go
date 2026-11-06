package dnsquery

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestParseServer(t *testing.T) {
	cases := []struct {
		in      string
		kind    string
		addr    string
		dohURL  string
		wantErr bool
	}{
		{"223.5.5.5", "udp", "223.5.5.5:53", "", false},
		{"223.5.5.5:5353", "udp", "223.5.5.5:5353", "", false},
		{"udp://1.1.1.1", "udp", "1.1.1.1:53", "", false},
		{"2001:4860:4860::8888", "udp", "[2001:4860:4860::8888]:53", "", false},
		{"tls://dns.alidns.com", "dot", "dns.alidns.com:853", "", false},
		{"dot://1.1.1.1:853", "dot", "1.1.1.1:853", "", false},
		{"https://dns.cloudflare.com/dns-query", "doh", "", "https://dns.cloudflare.com/dns-query", false},
		{"https://dns.alidns.com", "doh", "", "https://dns.alidns.com/dns-query", false},
		{"quic://dns.adguard-dns.com", "", "", "", true},
		{"doq://dns.adguard-dns.com", "", "", "", true},
		{"http://dns.alidns.com/dns-query", "", "", "", true},
		{"", "", "", "", true},
		{"dns.alidns.com", "", "", "", true},
	}
	for _, c := range cases {
		up, err := parseServer(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseServer(%q) 应报错，实际得到 %+v", c.in, up)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseServer(%q) 报错: %v", c.in, err)
			continue
		}
		if up.kind != c.kind {
			t.Errorf("parseServer(%q).kind = %q, want %q", c.in, up.kind, c.kind)
		}
		if up.kind != "doh" && up.addr != c.addr {
			t.Errorf("parseServer(%q).addr = %q, want %q", c.in, up.addr, c.addr)
		}
		if up.kind == "doh" && up.url != c.dohURL {
			t.Errorf("parseServer(%q).url = %q, want %q", c.in, up.url, c.dohURL)
		}
	}
}

// 构造一个带 0xC0 压缩指针的真实 A 应答。
func responseWithPointer(t *testing.T, id uint16) []byte {
	t.Helper()
	return buildAResponse(id)
}

func buildAResponse(id uint16) []byte {
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

func TestCollectDoH(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if len(body) < 12 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(buildAResponse(binary.BigEndian.Uint16(body[:2])))
	}))
	defer srv.Close()

	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	ips, err := CollectWithOptions(context.Background(), "www.example.com", []string{srv.URL + "/dns-query"}, Options{
		Timeout: 3 * time.Second, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("DoH 结果 = %v, want [93.184.216.34]", ips)
	}
}

func makeTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"dns.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startDoTServer(t *testing.T) (string, *x509.CertPool) {
	t.Helper()
	cert := makeTestCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lenBuf [2]byte
				if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
				if _, err := io.ReadFull(c, query); err != nil || len(query) < 12 {
					return
				}
				resp := buildAResponse(binary.BigEndian.Uint16(query[:2]))
				frame := make([]byte, 2+len(resp))
				binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
				copy(frame[2:], resp)
				_, _ = c.Write(frame)
			}(conn)
		}
	}()
	return ln.Addr().String(), roots
}

func TestCollectDoT(t *testing.T) {
	addr, roots := startDoTServer(t)
	ips, err := CollectWithOptions(context.Background(), "www.example.com", []string{"tls://" + addr}, Options{
		Timeout: 3 * time.Second, RootCAs: roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("DoT 结果 = %v, want [93.184.216.34]", ips)
	}
}

func TestValidateServerRejectsDoQ(t *testing.T) {
	if err := ValidateServer("quic://dns.adguard-dns.com"); err == nil {
		t.Fatal("DoQ 应返回不支持错误")
	}
	if err := ValidateServer("tls://dns.alidns.com"); err != nil {
		t.Fatalf("DoT 地址应通过校验: %v", err)
	}
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
