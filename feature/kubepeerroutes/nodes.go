// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package kubepeerroutes

import (
	"context"
	"net/netip"
	"slices"
	"time"

	"go4.org/netipx"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

type kubeNode struct {
	name     string
	addrs    []netip.Addr // InternalIP addresses
	podCIDRs []netip.Prefix
}

func listNodes(ctx context.Context, kubeconfigPath string) ([]kubeNode, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = 15 * time.Second
	client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	// ResourceVersion "0" is served from the apiserver's cache.
	list, err := client.Nodes().List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return nil, err
	}
	out := make([]kubeNode, 0, len(list.Items))
	for _, n := range list.Items {
		out = append(out, fromNode(&n))
	}
	return out, nil
}

func fromNode(n *corev1.Node) kubeNode {
	kn := kubeNode{name: n.Name}
	for _, a := range n.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		if ip, err := netip.ParseAddr(a.Address); err == nil {
			kn.addrs = append(kn.addrs, ip)
		}
	}
	cidrs := n.Spec.PodCIDRs
	if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
		cidrs = []string{n.Spec.PodCIDR}
	}
	for _, s := range cidrs {
		if p, err := netip.ParsePrefix(s); err == nil {
			kn.podCIDRs = append(kn.podCIDRs, p.Masked())
		}
	}
	return kn
}

// build matches the cluster's nodes to peers by address. A pod CIDR claimed by
// more than one node is left out, so that no peer is given another's pods.
func build(self string, nodes []kubeNode, selfAddrs []netip.Prefix, peers []tailcfg.NodeView, logf logger.Logf) *state {
	owners := map[netip.Prefix]int{}
	for _, n := range nodes {
		for _, p := range n.podCIDRs {
			owners[p]++
		}
	}

	byAddr := map[netip.Addr]kubeNode{}
	var src, dst, pods netipx.IPSetBuilder
	for _, n := range nodes {
		for _, a := range n.addrs {
			byAddr[a] = n
			src.Add(a)
		}
		for _, p := range n.podCIDRs {
			if owners[p] > 1 {
				continue
			}
			src.AddPrefix(p)
			pods.AddPrefix(p)
			if n.name == self {
				dst.AddPrefix(p)
			}
		}
	}
	for _, p := range selfAddrs {
		dst.AddPrefix(p)
	}
	for p, c := range owners {
		if c > 1 {
			logf("pod CIDR %v is claimed by %d nodes; not routing it", p, c)
		}
	}

	st := &state{peers: map[tailcfg.NodeID][]netip.Prefix{}}
	for _, peer := range peers {
		for _, a := range peer.Addresses().All() {
			n, ok := byAddr[a.Addr()]
			if !ok || n.name == self {
				continue
			}
			var mine []netip.Prefix
			for _, p := range n.podCIDRs {
				if owners[p] == 1 {
					mine = append(mine, p)
				}
			}
			if len(mine) > 0 {
				slices.SortFunc(mine, netip.Prefix.Compare)
				st.peers[peer.ID()] = mine
			}
			break
		}
	}
	st.src, _ = src.IPSet()
	st.dst, _ = dst.IPSet()
	st.pods, _ = pods.IPSet()
	return st
}
