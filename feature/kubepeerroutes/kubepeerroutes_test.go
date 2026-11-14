// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package kubepeerroutes

import (
	"net/netip"
	"reflect"
	"testing"

	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
)

func pfxs(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func peer(id tailcfg.NodeID, a ...string) tailcfg.NodeView {
	var ps []netip.Prefix
	for _, s := range a {
		ps = append(ps, netip.PrefixFrom(netip.MustParseAddr(s), 32))
	}
	return (&tailcfg.Node{ID: id, Addresses: ps}).View()
}

var testNodes = []kubeNode{
	{name: "self", addrs: addrs("100.64.0.1"), podCIDRs: pfxs("10.244.0.0/24")},
	{name: "b", addrs: addrs("100.64.0.2"), podCIDRs: pfxs("10.244.1.0/24")},
	{name: "c", addrs: addrs("100.64.0.3"), podCIDRs: pfxs("10.244.2.0/24")},
	{name: "dup1", addrs: addrs("100.64.0.4"), podCIDRs: pfxs("10.244.9.0/24")},
	{name: "dup2", addrs: addrs("100.64.0.5"), podCIDRs: pfxs("10.244.9.0/24")},
}

func TestBuildPeers(t *testing.T) {
	peers := []tailcfg.NodeView{
		peer(2, "100.64.0.2"),
		peer(3, "100.64.0.3"),
		peer(4, "100.64.0.4"),
		peer(7, "100.64.0.7"), // in the tailnet, not in the cluster
	}
	st := build("self", testNodes, pfxs("100.64.0.1/32"), peers, t.Logf)
	want := map[tailcfg.NodeID][]netip.Prefix{
		2: pfxs("10.244.1.0/24"),
		3: pfxs("10.244.2.0/24"),
	}
	if !reflect.DeepEqual(st.peers, want) {
		t.Errorf("peers = %v, want %v", st.peers, want)
	}
}

func TestAllowIngress(t *testing.T) {
	e := &extension{}
	e.state.Store(build("self", testNodes, pfxs("100.64.0.1/32"), nil, t.Logf))

	tests := []struct {
		src, dst string
		want     bool
	}{
		{"10.244.1.5", "10.244.0.9", true},  // pod to pod
		{"100.64.0.2", "10.244.0.9", true},  // node to pod
		{"10.244.1.5", "100.64.0.1", true},  // pod to node
		{"100.64.0.2", "100.64.0.1", false}, // node to node: the ACL decides
		{"100.64.0.7", "10.244.0.9", false}, // not a node of the cluster
		{"10.244.9.5", "10.244.0.9", false}, // duplicated pod CIDR
		{"10.244.1.5", "10.244.2.9", false}, // pods of another node
	}
	for _, tt := range tests {
		var p packet.Parsed
		p.Src = netip.AddrPortFrom(netip.MustParseAddr(tt.src), 1234)
		p.Dst = netip.AddrPortFrom(netip.MustParseAddr(tt.dst), 80)
		if got, _ := e.allowIngress(p); got != tt.want {
			t.Errorf("%s -> %s: got %v, want %v", tt.src, tt.dst, got, tt.want)
		}
	}
}

func TestAllowIngressWithoutState(t *testing.T) {
	var p packet.Parsed
	p.Src = netip.AddrPortFrom(netip.MustParseAddr("10.244.1.5"), 1234)
	p.Dst = netip.AddrPortFrom(netip.MustParseAddr("10.244.0.9"), 80)
	if got, _ := (&extension{}).allowIngress(p); got {
		t.Error("accepted before the first read of the nodes")
	}
}
