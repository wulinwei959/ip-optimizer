package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// startTestTLS 用自签 CA 起一个本地 TLS 服务，返回根证书池与端口。
func startTestTLS(t *testing.T, dnsName string) (*x509.CertPool, int) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "hosts-optimizer test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return pool, raw.Addr().(*net.TCPAddr).Port
}

func newTestChecker(sni string, port int, pool *x509.CertPool) *Checker {
	return New(Options{
		SNI: sni, Port: port, Rounds: 1,
		Timeout: 2 * time.Second, RootCAs: pool,
	})
}

func TestCheckAcceptsMatchingSNICertificate(t *testing.T) {
	pool, port := startTestTLS(t, "good.test")
	r, err := newTestChecker("good.test", port, pool).Check(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("正确 SNI 应通过 TLS 校验，得到错误: %v", err)
	}
	if !r.TLSChecked || r.IP != "127.0.0.1" {
		t.Fatalf("结果异常: %+v", r)
	}
}

func TestCheckRejectsWrongSNI(t *testing.T) {
	pool, port := startTestTLS(t, "good.test")
	// 端口开着、证书链也可信，但证书不覆盖 evil.test —— 必须被淘汰
	if _, err := newTestChecker("evil.test", port, pool).Check(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("证书主机名不匹配时必须淘汰该 IP")
	}
}

func TestCheckRejectsUntrustedCA(t *testing.T) {
	_, port := startTestTLS(t, "good.test")
	// 空根证书池：自签证书链不可信，必须淘汰
	if _, err := newTestChecker("good.test", port, x509.NewCertPool()).Check(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("证书链不可信时必须淘汰该 IP")
	}
}

func TestCheckRejectsPlainTCPPort(t *testing.T) {
	// 端口能连上但不是 TLS 服务 —— 「TCP 连得上」不等于「IP 可用」
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	if _, err := newTestChecker("good.test", port, x509.NewCertPool()).Check(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("非 TLS 端口必须被淘汰")
	}
}
