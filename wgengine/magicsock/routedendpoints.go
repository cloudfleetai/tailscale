// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
)

// subnetRoutes returns the prefixes n routes for others: its allowed IPs
// without its own addresses and without default routes.
//
// An address inside one of them is reached through n's tunnel, so it cannot
// also be an endpoint of that tunnel.
func subnetRoutes(n tailcfg.NodeView) []netip.Prefix {
	var out []netip.Prefix
	add := func(p netip.Prefix) {
		if p.Bits() == 0 || slices.Contains(out, p) {
			return
		}
		for _, a := range n.Addresses().All() {
			if a == p {
				return
			}
		}
		out = append(out, p)
	}
	for _, p := range n.AllowedIPs().All() {
		add(p)
	}
	if hi := n.Hostinfo(); hi.Valid() {
		for _, p := range hi.RoutableIPs().All() {
			add(p)
		}
	}
	return out
}

func prefixesContain(routes []netip.Prefix, a netip.Addr) bool {
	for _, p := range routes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
