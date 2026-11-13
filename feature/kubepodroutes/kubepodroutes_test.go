// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package kubepodroutes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"tailscale.com/ipn"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestMergeRoutes(t *testing.T) {
	tests := []struct {
		name          string
		cur, old, add []netip.Prefix
		want          []netip.Prefix
	}{
		{"first", nil, nil, prefixes("10.244.1.0/24"), prefixes("10.244.1.0/24")},
		{"keeps others", prefixes("192.168.0.0/24"), nil, prefixes("10.244.1.0/24"), prefixes("10.244.1.0/24", "192.168.0.0/24")},
		{"already there", prefixes("10.244.1.0/24"), prefixes("10.244.1.0/24"), prefixes("10.244.1.0/24"), prefixes("10.244.1.0/24")},
		{"replaces its own", prefixes("10.244.1.0/24", "192.168.0.0/24"), prefixes("10.244.1.0/24"), prefixes("10.244.2.0/24"), prefixes("10.244.2.0/24", "192.168.0.0/24")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeRoutes(tt.cur, tt.old, tt.add); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func kubeconfigFor(t *testing.T, srv *httptest.Server, token string) string {
	t.Helper()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: ctx
  context: {cluster: c, user: u}
users:
- name: u
  user: {token: %s}
`, srv.URL, base64.StdEncoding.EncodeToString(ca), token)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFetchPodCIDRs(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want []netip.Prefix
	}{
		{"dual stack", `{"podCIDR":"10.244.3.0/24","podCIDRs":["10.244.3.0/24","fd00:3::/64"]}`, prefixes("10.244.3.0/24", "fd00:3::/64")},
		{"legacy field only", `{"podCIDR":"10.244.3.0/24"}`, prefixes("10.244.3.0/24")},
		{"not assigned yet", `{}`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/nodes/node-1" || r.Header.Get("Authorization") != "Bearer secret" {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1"},"spec":%s}`, tt.spec)
			}))
			defer srv.Close()
			got, err := fetchPodCIDRs(t.Context(), kubeconfigFor(t, srv, "secret"), "node-1")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// A kubelet kubeconfig authenticates with certificate files.
func TestFetchPodCIDRsClientCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "system:node:node-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != "system:node:node-1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1"},"spec":{"podCIDRs":["10.244.3.0/24"]}}`)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	write := func(name string, data []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	write("client.pem", append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...))
	write("kubeconfig", fmt.Appendf(nil, `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster: {server: %s, certificate-authority: ca.crt}
contexts:
- name: ctx
  context: {cluster: c, user: u}
users:
- name: u
  user: {client-certificate: client.pem, client-key: client.pem}
`, srv.URL))

	got, err := fetchPodCIDRs(t.Context(), filepath.Join(dir, "kubeconfig"), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("10.244.3.0/24"); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFetchPodCIDRsErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := fetchPodCIDRs(t.Context(), kubeconfigFor(t, srv, "wrong"), "node-1"); err == nil {
		t.Error("no error for a rejected request")
	}
	if _, err := fetchPodCIDRs(t.Context(), filepath.Join(t.TempDir(), "missing"), "node-1"); err == nil {
		t.Error("no error for a missing kubeconfig")
	}
}

type fakeBackend struct {
	prefs *ipn.Prefs
	edits int
}

func (f *fakeBackend) Prefs() ipn.PrefsView { return f.prefs.View() }

func (f *fakeBackend) EditPrefs(mp *ipn.MaskedPrefs) (ipn.PrefsView, error) {
	f.edits++
	f.prefs.ApplyEdits(mp)
	return f.prefs.View(), nil
}

func TestAdvertise(t *testing.T) {
	fb := &fakeBackend{prefs: &ipn.Prefs{AdvertiseRoutes: prefixes("192.168.0.0/24")}}
	e := &extension{logf: t.Logf, ed: fb}
	for range 2 {
		if err := e.advertise(prefixes("10.244.3.0/24")); err != nil {
			t.Fatal(err)
		}
	}
	if want := prefixes("10.244.3.0/24", "192.168.0.0/24"); !reflect.DeepEqual(fb.prefs.AdvertiseRoutes, want) {
		t.Errorf("routes = %v, want %v", fb.prefs.AdvertiseRoutes, want)
	}
	if fb.edits != 1 {
		t.Errorf("prefs edited %d times, want 1", fb.edits)
	}
}
