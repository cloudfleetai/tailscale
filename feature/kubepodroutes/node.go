// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package kubepodroutes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"
)

// kubeconfig is the subset of a kubeconfig file needed to reach the API
// server as one user.
type kubeconfig struct {
	CurrentContext string `json:"current-context"`
	Clusters       []struct {
		Name    string `json:"name"`
		Cluster struct {
			Server string `json:"server"`
			CA     string `json:"certificate-authority"`
			CAData []byte `json:"certificate-authority-data"`
		} `json:"cluster"`
	} `json:"clusters"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			Cluster string `json:"cluster"`
			User    string `json:"user"`
		} `json:"context"`
	} `json:"contexts"`
	Users []struct {
		Name string `json:"name"`
		User struct {
			Cert     string `json:"client-certificate"`
			CertData []byte `json:"client-certificate-data"`
			Key      string `json:"client-key"`
			KeyData  []byte `json:"client-key-data"`
			Token    string `json:"token"`
		} `json:"user"`
	} `json:"users"`
}

// fetchPodCIDRs returns the pod CIDRs the cluster assigned to the named node.
// The kubeconfig and the files it points to are read on every call, so
// rotated client certificates are picked up.
func fetchPodCIDRs(ctx context.Context, kubeconfigPath, node string) ([]netip.Prefix, error) {
	raw, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(raw, &kc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", kubeconfigPath, err)
	}
	var clusterName, userName string
	for _, c := range kc.Contexts {
		if c.Name == kc.CurrentContext {
			clusterName, userName = c.Context.Cluster, c.Context.User
		}
	}
	// Paths in a kubeconfig are relative to the file.
	read := func(path string, data []byte) ([]byte, error) {
		if len(data) > 0 || path == "" {
			return data, nil
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(filepath.Dir(kubeconfigPath), path)
		}
		return os.ReadFile(path)
	}

	var server string
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	for _, c := range kc.Clusters {
		if c.Name != clusterName {
			continue
		}
		server = c.Cluster.Server
		ca, err := read(c.Cluster.CA, c.Cluster.CAData)
		if err != nil {
			return nil, err
		}
		if len(ca) > 0 {
			tlsConf.RootCAs = x509.NewCertPool()
			if !tlsConf.RootCAs.AppendCertsFromPEM(ca) {
				return nil, errors.New("no certificate in the cluster's certificate authority")
			}
		}
	}
	if server == "" {
		return nil, fmt.Errorf("no server for context %q in %s", kc.CurrentContext, kubeconfigPath)
	}
	var token string
	for _, u := range kc.Users {
		if u.Name != userName {
			continue
		}
		token = u.User.Token
		cert, err := read(u.User.Cert, u.User.CertData)
		if err != nil {
			return nil, err
		}
		key, err := read(u.User.Key, u.User.KeyData)
		if err != nil {
			return nil, err
		}
		if len(cert) > 0 {
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("client certificate: %w", err)
			}
			tlsConf.Certificates = []tls.Certificate{pair}
		}
	}

	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", server+"/api/v1/nodes/"+url.PathEscape(node), nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	tr := &http.Transport{TLSClientConfig: tlsConf}
	defer tr.CloseIdleConnections()
	res, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API server: %s", res.Status)
	}
	var n struct {
		Spec struct {
			PodCIDR  string   `json:"podCIDR"`
			PodCIDRs []string `json:"podCIDRs"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(res.Body).Decode(&n); err != nil {
		return nil, err
	}
	cidrs := n.Spec.PodCIDRs
	if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
		cidrs = []string{n.Spec.PodCIDR}
	}
	var out []netip.Prefix
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
