// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package kubepodroutes

import (
	"context"
	"net/netip"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// fetchPodCIDRs returns the pod CIDRs the cluster assigned to the named node.
func fetchPodCIDRs(ctx context.Context, kubeconfigPath, node string) ([]netip.Prefix, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	cfg.Timeout = 15 * time.Second
	client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	n, err := client.Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
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
