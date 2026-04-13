package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/roberttkach/ncapd/internal/config"
)

func TestBuildTLSConfig_InvalidPaths(t *testing.T) {
	cfg := config.TLS{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for nonexistent cert files, got nil")
	}
}

func TestBuildTLSConfig_Valid(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	cfg := config.TLS{
		CertFile: certFile,
		KeyFile:  keyFile,
	}

	tc, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}

	if len(tc.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tc.Certificates))
	}
	if tc.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%04x, want 0x%04x", tc.MinVersion, tls.VersionTLS12)
	}
	if tc.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", tc.ClientAuth)
	}
}

func TestBuildTLSConfig_MTLS(t *testing.T) {
	certFile, keyFile := generateTestCert(t)
	caFile := generateTestCA(t)

	cfg := config.TLS{
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: caFile,
	}

	tc, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig() error = %v", err)
	}

	if tc.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", tc.ClientAuth)
	}
	if tc.ClientCAs == nil {
		t.Error("expected ClientCAs to be set for mTLS")
	}
}

func TestBuildTLSConfig_MissingKey(t *testing.T) {
	certFile, _ := generateTestCert(t)

	cfg := config.TLS{
		CertFile: certFile,
		KeyFile:  "/nonexistent/key.pem",
	}

	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for missing key file, got nil")
	}
}

func TestBuildTLSConfig_MissingCert(t *testing.T) {
	_, keyFile := generateTestCert(t)

	cfg := config.TLS{
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  keyFile,
	}

	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for missing cert file, got nil")
	}
}

func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	cfg := config.TLS{
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: "/nonexistent/ca.pem",
	}

	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for nonexistent CA file, got nil")
	}
}

func TestBuildTLSConfig_InvalidCAPEM(t *testing.T) {
	certFile, keyFile := generateTestCert(t)

	dir := t.TempDir()
	badCAFile := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(badCAFile, []byte("this is not PEM data"), 0644); err != nil {
		t.Fatalf("write bad CA file: %v", err)
	}

	cfg := config.TLS{
		CertFile:     certFile,
		KeyFile:      keyFile,
		ClientCAFile: badCAFile,
	}

	_, err := buildTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for invalid CA PEM data, got nil")
	}
}

func generateTestCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyOut.Close()

	return certFile, keyFile
}

func generateTestCA(t *testing.T) string {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TestCA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")

	caOut, err := os.Create(caFile)
	if err != nil {
		t.Fatalf("create CA file: %v", err)
	}
	if err := pem.Encode(caOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode CA cert: %v", err)
	}
	caOut.Close()

	return caFile
}
