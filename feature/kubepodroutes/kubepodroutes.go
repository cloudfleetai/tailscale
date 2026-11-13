// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package kubepodroutes advertises a Kubernetes node's pod CIDRs as subnet
// routes.
//
// With every node of a cluster doing so, pod traffic between nodes can be
// routed over Tailscale as it is, without an overlay network on top. The node
// reads its own Node object from the API server with the kubeconfig named by
// TS_KUBE_POD_ROUTES_KUBECONFIG, typically the kubelet's.
package kubepodroutes

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/types/logger"
)

const featureName = "kubepodroutes"

var (
	kubeconfigPath = envknob.RegisterString("TS_KUBE_POD_ROUTES_KUBECONFIG")
	nodeNameKnob   = envknob.RegisterString("TS_KUBE_POD_ROUTES_NODE") // defaults to the hostname
)

const (
	retryInterval   = 5 * time.Second // until the node has pod CIDRs
	refreshInterval = 5 * time.Minute // afterwards
)

func init() {
	if !feature.Register(featureName) {
		return
	}
	ipnext.RegisterExtension(featureName, newExtension)
}

// prefsEditor is the part of ipnlocal.LocalBackend the extension uses.
type prefsEditor interface {
	Prefs() ipn.PrefsView
	EditPrefs(*ipn.MaskedPrefs) (ipn.PrefsView, error)
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	path := kubeconfigPath()
	if path == "" {
		return nil, ipnext.SkipExtension
	}
	ed, ok := sb.(prefsEditor)
	if !ok {
		return nil, errors.New("backend cannot edit prefs")
	}
	node := nodeNameKnob()
	if node == "" {
		var err error
		if node, err = os.Hostname(); err != nil {
			return nil, err
		}
	}
	return &extension{
		logf:       logger.WithPrefix(logf, featureName+": "),
		ed:         ed,
		kubeconfig: path,
		node:       node,
	}, nil
}

type extension struct {
	logf       logger.Logf
	ed         prefsEditor
	kubeconfig string
	node       string

	cancel context.CancelFunc
	wg     sync.WaitGroup

	managed []netip.Prefix // routes this extension added; only touched by run
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension].
func (e *extension) Init(ipnext.Host) error {
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
		wait := retryInterval
		cidrs, err := fetchPodCIDRs(ctx, e.kubeconfig, e.node)
		switch {
		case err != nil:
			// The kubeconfig does not exist until kubelet has bootstrapped,
			// so failing here is the normal state of a new node.
			if s := err.Error(); s != lastErr {
				e.logf("reading node %q: %v", e.node, err)
				lastErr = s
			}
		case len(cidrs) > 0:
			lastErr = ""
			if err := e.advertise(cidrs); err != nil {
				e.logf("advertising %v: %v", cidrs, err)
			} else {
				wait = refreshInterval
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// advertise makes the node's advertised routes include cidrs, replacing the
// ones a previous call added and leaving routes set by anyone else alone.
func (e *extension) advertise(cidrs []netip.Prefix) error {
	cur := e.ed.Prefs().AdvertiseRoutes().AsSlice()
	want := mergeRoutes(cur, e.managed, cidrs)
	e.managed = cidrs
	if slices.Equal(want, cur) {
		return nil
	}
	_, err := e.ed.EditPrefs(&ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: want},
		AdvertiseRoutesSet: true,
	})
	if err == nil {
		e.logf("advertising pod CIDRs %v", cidrs)
	}
	return err
}

// mergeRoutes returns cur without the routes in old, plus those in add.
func mergeRoutes(cur, old, add []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range cur {
		if !slices.Contains(old, p) && !slices.Contains(add, p) {
			out = append(out, p)
		}
	}
	out = append(out, add...)
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}
