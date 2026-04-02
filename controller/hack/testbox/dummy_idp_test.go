package main

import (
	"crypto/x509"
	"testing"
)

func TestBuildDummyIDPServerCertificate(t *testing.T) {
	tlsCert, err := buildDummyIDPServerCertificate()
	if err != nil {
		t.Fatalf("buildDummyIDPServerCertificate() error = %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected generated server certificate")
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	if leaf.IsCA {
		t.Fatal("expected generated server certificate to not be a CA")
	}
	if got, want := leaf.Subject.CommonName, "dummy-idp.default"; got != want {
		t.Fatalf("expected CommonName %q, got %q", want, got)
	}
	if len(leaf.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS names, got %v", leaf.DNSNames)
	}
}
