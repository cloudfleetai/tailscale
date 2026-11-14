// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package kubepeerroutes routes a Kubernetes cluster's pod network over the
// tailnet without subnet routes. It reads the cluster's Node objects with the
// kubelet's kubeconfig and treats each peer that is a node of the cluster as
// the owner of that node's pod CIDRs: they are added to the peer's WireGuard
// allowed IPs and to the OS routes, and pod traffic between the cluster's
// nodes is accepted. Nothing is advertised to or approved by the control
// server.
package kubepeerroutes

import (
	"context"
	"maps"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

const featureName = "kubepeerroutes"

const (
	kubeconfigPath  = "/etc/kubernetes/kubelet.conf"
	refreshInterval = 10 * time.Second
)

func init() {
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, newExtension)
}

func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	node, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return &extension{
		logf:       logger.WithPrefix(logf, featureName+": "),
		kubeconfig: kubeconfigPath,
		node:       node,
		list:       listNodes,
	}, nil
}

type extension struct {
	logf       logger.Logf
	kubeconfig string
	node       string
	list       func(ctx context.Context, kubeconfig string) ([]kubeNode, error)

	host   ipnext.Host
	cancel context.CancelFunc
	wg     sync.WaitGroup

	state atomic.Pointer[state]
}

// state is what the hooks read. It is replaced as a whole on each refresh.
type state struct {
	peers map[tailcfg.NodeID][]netip.Prefix // pod CIDRs per peer
	src   *netipx.IPSet                     // the cluster's pod CIDRs and node addresses
	dst   *netipx.IPSet                     // this node's pod CIDRs and addresses
	pods  *netipx.IPSet                     // the cluster's pod CIDRs
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
	e.host = host
	host.Hooks().ExtraPeerSubnets.Set(e.peerSubnets)
	host.Hooks().Filter.IngressAllowHooks.Add(e.allowIngress)

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.wg.Go(func() { e.run(ctx) })
	return nil
}

// Shutdown implements [ipnext.Extension].
func (e *extension) Shutdown() error {
	if e.cancel != nil {
		e.cancel()
		e.wg.Wait()
	}
	return nil
}

func (e *extension) run(ctx context.Context) {
	var lastErr string
	for {
		if err := e.refresh(ctx); err != nil {
			if s := err.Error(); s != lastErr {
				e.logf("reading nodes: %v", err)
				lastErr = s
			}
		} else {
			lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(refreshInterval):
		}
	}
}

// refresh rebuilds the state from the cluster's nodes and the current peers.
// A failed read keeps the previous state.
func (e *extension) refresh(ctx context.Context) error {
	nodes, err := e.list(ctx, e.kubeconfig)
	if err != nil {
		return err
	}
	nb := e.host.NodeBackend()
	st := build(e.node, nodes, nb.Self().Addresses().AsSlice(), nb.Peers(), e.logf)

	old := e.state.Swap(st)
	if old == nil || !maps.EqualFunc(old.peers, st.peers, slices.Equal) {
		e.logf("pod CIDRs for %d peers", len(st.peers))
		e.host.AuthReconfigAsync()
	}
	return nil
}

// peerSubnets implements [ipnext.Hooks.ExtraPeerSubnets].
func (e *extension) peerSubnets() map[tailcfg.NodeID][]netip.Prefix {
	if st := e.state.Load(); st != nil {
		return st.peers
	}
	return nil
}

// allowIngress accepts pod traffic between the cluster's nodes. WireGuard has
// already checked that the source belongs to the peer that sent it.
func (e *extension) allowIngress(p packet.Parsed) (bool, string) {
	st := e.state.Load()
	if st == nil {
		return false, ""
	}
	src, dst := p.Src.Addr(), p.Dst.Addr()
	if !st.dst.Contains(dst) || !st.src.Contains(src) {
		return false, ""
	}
	// Node to node is the ACL's business.
	if !st.pods.Contains(src) && !st.pods.Contains(dst) {
		return false, ""
	}
	return true, "kubepeerroutes"
}
