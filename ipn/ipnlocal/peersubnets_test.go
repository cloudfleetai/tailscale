// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
)

func TestAppendPeerSubnets(t *testing.T) {
	p := netip.MustParsePrefix
	routes := []netip.Prefix{p("100.64.0.0/10")}
	got := appendPeerSubnets(routes, map[tailcfg.NodeID][]netip.Prefix{
		2: {p("10.244.2.0/24")},
		1: {p("10.244.1.0/24"), p("10.244.2.0/24")},
	})
	want := []netip.Prefix{p("100.64.0.0/10"), p("10.244.1.0/24"), p("10.244.2.0/24")}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
