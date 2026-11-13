// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"slices"
	"time"

	"tailscale.com/tstime/mono"
)

// LANCandidates returns every private IPv4 address that a peer advertises as
// an endpoint.
func (c *Conn) LANCandidates() []netip.Addr {
	var ret []netip.Addr
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(de *endpoint) {
		de.mu.Lock()
		defer de.mu.Unlock()
		for ap := range de.endpointState {
			if a := ap.Addr(); a.Is4() && a.IsPrivate() {
				ret = append(ret, a)
			}
		}
	})
	slices.SortFunc(ret, netip.Addr.Compare)
	return slices.Compact(ret)
}

// LANPeers reports the private IPv4 endpoints of each peer that answered a
// disco ping within maxAge, keyed by the peer's Tailscale IPv4 address. Only
// addresses that allow accepts are considered.
//
// If probe is set it also pings those addresses, so a path stays verified
// while it carries no WireGuard traffic. These pings never change the path
// WireGuard itself uses.
func (c *Conn) LANPeers(maxAge time.Duration, probe bool, allow func(netip.Addr) bool) map[netip.Addr][]netip.Addr {
	now := mono.Now()
	ret := make(map[netip.Addr][]netip.Addr)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(de *endpoint) {
		de.mu.Lock()
		defer de.mu.Unlock()
		if de.expired || !de.nodeAddr.Is4() {
			return
		}
		for ap, st := range de.endpointState {
			a := ap.Addr()
			if !a.Is4() || !a.IsPrivate() || !allow(a) {
				continue
			}
			if len(st.recentPongs) > 0 && now.Sub(st.recentPongs[st.recentPong].pongAt) <= maxAge {
				ret[de.nodeAddr] = append(ret[de.nodeAddr], a)
			}
			if probe {
				de.startDiscoPingLocked(epAddr{ap: ap}, now, pingLANBypass, 0, nil)
			}
		}
		slices.SortFunc(ret[de.nodeAddr], netip.Addr.Compare)
	})
	return ret
}

// SetOverlayAddrs sets the peer endpoint addresses that this node reaches
// through an overlay network running on top of Tailscale. WireGuard is never
// sent to them: such a path would put the tunnel inside the overlay that it
// carries.
func (c *Conn) SetOverlayAddrs(addrs []netip.Addr) {
	m := make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		m[a] = struct{}{}
	}
	c.overlayAddrs.Store(&m)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.peerMap.forEachEndpoint(func(de *endpoint) {
		de.mu.Lock()
		defer de.mu.Unlock()
		if _, ok := m[de.bestAddr.ap.Addr()]; ok && !de.bestAddr.vni.IsSet() {
			de.clearBestAddrLocked()
		}
	})
}

func (c *Conn) isOverlayAddr(a netip.Addr) bool {
	m := c.overlayAddrs.Load()
	if m == nil {
		return false
	}
	_, ok := (*m)[a]
	return ok
}
